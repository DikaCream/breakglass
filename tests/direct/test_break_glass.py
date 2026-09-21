"""BreakGlass direct-mode tests: the breaker, its guards, and the vault gate.

Everything here runs in a local VM with mocked validators, so the deterministic
rule set is covered exhaustively. The live consensus path is covered by the
StudioNet integration tests.
"""

import json

import pytest

from tests.direct.conftest import set_time

# ----------------------------------------------------------------- fixtures
BAIL = 10**17          # 0.1 GEN
BOND = 10**16          # 0.01 GEN
REWARD = BAIL // 4     # a valid alarm pays a quarter of the bail

ALARM_URL = "https://report.example/poc"
ARCHIVE_URL = "https://vault.example/audit"
FIX_URL = "https://patch.example/fix"


def _reset():
    import genlayer.gl.genvm_contracts as gvc

    gvc.__known_contract__ = None  # the direct loader does not reset this


@pytest.fixture()
def breaker(direct_vm, direct_deploy):
    c = direct_deploy("contracts/break_glass.py")
    yield c
    _reset()


def _register(breaker, vm, who, addr_hex=None, bail=BAIL, label="safe-vault"):
    vm.sender = who
    vm.value = bail
    tid = int(breaker.register_target(addr_hex or "0x" + "11" * 20, label, ARCHIVE_URL))
    vm.value = 0
    return tid


def _alarm(breaker, vm, who, tid, url=ALARM_URL, reason="Withdrawal bypass via reentrancy", bond=BOND):
    vm.sender = who
    vm.value = bond
    aid = int(breaker.file_alarm(tid, url, reason))
    vm.value = 0
    return aid


def _mock_exploit(vm, nonce, fix_hash="a1b2c3d4e5f60718"):
    page = json.dumps(
        {
            "report": "PoC: withdraw() drains another user's balance",
            "tx_trace": "0xabc123",
            "audit_nonce": nonce,
        }
    )
    vm.mock_web(r"https://report\.example/poc", {"status": 200, "body": page})
    vm.mock_llm(
        r".*emergency alarm.*",
        json.dumps(
            {
                "verdict": "EXPLOITED",
                "nonce": nonce,
                "fix_hash": fix_hash,
                "reasoning": "The report shows a working drain with a trace.",
            }
        ),
    )


def _mock_unproven(vm, nonce):
    page = json.dumps({"report": "I think there might be an issue someday", "audit_nonce": nonce})
    vm.mock_web(r"https://report\.example/poc", {"status": 200, "body": page})
    vm.mock_llm(
        r".*emergency alarm.*",
        json.dumps(
            {
                "verdict": "UNPROVEN",
                "nonce": nonce,
                "fix_hash": "",
                "reasoning": "The report describes a hypothetical, no working exploit.",
            }
        ),
    )


def _mock_unreachable(vm):
    # The direct web mock returns any registered mock's body regardless of
    # status, so a dark page is simulated by leaving the URL unmocked.
    pass


def _mock_fix(vm):
    page = json.dumps({"patch": "checks added to withdraw", "diff": "-balance check"})
    vm.mock_web(r"https://patch\.example/fix", {"status": 200, "body": page})
    vm.mock_llm(
        r".*verifying a fix.*",
        json.dumps(
            {
                "verdict": "FIXED",
                "fix_hash": "a1b2c3d4e5f60718",
                "reasoning": "The diff adds the missing balance check.",
            }
        ),
    )


# ------------------------------------------------------------------ register
def test_register_target(breaker, direct_vm, direct_alice):
    tid = _register(breaker, direct_vm, direct_alice)
    t = breaker.get_target(tid)
    assert t["status"] == "LIVE"
    assert int(t["bail"]) == BAIL
    stats = breaker.get_stats()
    assert int(stats["total_bail"]) == BAIL
    assert int(stats["live"]) == 1


def test_register_reverts_below_min_bail(breaker, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = BAIL // 2
    with pytest.raises(Exception, match="bail is below"):
        breaker.register_target("0x" + "11" * 20, "v", ARCHIVE_URL)
    direct_vm.value = 0


@pytest.mark.parametrize("url", ["ftp://x.example/a", "not a url", ""])
def test_register_reverts_bad_url(breaker, direct_vm, direct_alice, url):
    direct_vm.sender = direct_alice
    direct_vm.value = BAIL
    with pytest.raises(Exception):
        breaker.register_target("0x" + "11" * 20, "v", url)
    direct_vm.value = 0


def test_register_reverts_bad_label(breaker, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = BAIL
    with pytest.raises(Exception, match="label"):
        breaker.register_target("0x" + "11" * 20, "", ARCHIVE_URL)
    direct_vm.value = 0


# --------------------------------------------------------------- file alarm
def test_file_alarm(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    a = breaker.get_alarm(aid)
    assert a["status"] == "PENDING"
    assert int(a["bond"]) == BOND
    t = breaker.get_target(tid)
    assert int(t["active_alarm_id"]) == aid
    stats = breaker.get_stats()
    assert int(stats["total_bonds"]) == BOND


def test_second_alarm_rejected_while_open(breaker, direct_vm, direct_alice, direct_bob, direct_charlie):
    tid = _register(breaker, direct_vm, direct_alice)
    _alarm(breaker, direct_vm, direct_bob, tid)
    direct_vm.sender = direct_charlie
    direct_vm.value = BOND
    with pytest.raises(Exception, match="already has an alarm"):
        breaker.file_alarm(tid, ALARM_URL, "another finding")
    direct_vm.value = 0


def test_owner_cannot_alarm_own_target(breaker, direct_vm, direct_alice):
    tid = _register(breaker, direct_vm, direct_alice)
    direct_vm.sender = direct_alice
    direct_vm.value = BOND
    with pytest.raises(Exception, match="owner cannot alarm"):
        breaker.file_alarm(tid, ALARM_URL, "self alarm")
    direct_vm.value = 0


def test_alarm_rejected_on_paused_target(breaker, direct_vm, direct_alice, direct_bob, direct_charlie):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce)
    breaker.review_alarm(aid)
    direct_vm.sender = direct_charlie
    direct_vm.value = BOND
    with pytest.raises(Exception, match="only accepted on a live"):
        breaker.file_alarm(tid, ALARM_URL, "second alarm on paused")
    direct_vm.value = 0


# ------------------------------------------------------------------- review
def test_valid_alarm_pauses_and_pays(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce)
    breaker.review_alarm(aid)

    a = breaker.get_alarm(aid)
    assert a["status"] == "VALID"
    assert a["verdict"] == "EXPLOITED"
    t = breaker.get_target(tid)
    assert t["status"] == "EXPLOITED"
    assert t["last_fix_hash"] == "a1b2c3d4e5f60718"

    stats = breaker.get_stats()
    assert int(stats["total_bail"]) == BAIL - REWARD
    assert int(stats["total_bonds"]) == 0
    assert int(stats["total_paid"]) == REWARD
    assert int(stats["paused"]) == 1


def test_unproven_alarm_burns_bond_to_bail(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_unproven(direct_vm, nonce)
    breaker.review_alarm(aid)

    a = breaker.get_alarm(aid)
    assert a["status"] == "REJECTED"
    t = breaker.get_target(tid)
    assert t["status"] == "LIVE"
    stats = breaker.get_stats()
    # The reporter's bond burned into the bail.
    assert int(stats["total_bail"]) == BAIL + BOND
    assert int(stats["total_bonds"]) == 0
    assert int(stats["total_paid"]) == 0


def test_nonceless_report_falsifies_even_with_perfect_content(breaker, direct_vm, direct_alice, direct_bob):
    """The frozen-page attack: a perfect report written before the alarm."""
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)

    page = json.dumps({"report": "PoC: full drain", "audit_nonce": "0" * 32})
    direct_vm.mock_web(r"https://report\.example/poc", {"status": 200, "body": page})
    # The judge says EXPLOITED with a stale nonce: the contract must override.
    direct_vm.mock_llm(
        r".*emergency alarm.*",
        json.dumps(
            {
                "verdict": "EXPLOITED",
                "nonce": "0" * 32,
                "fix_hash": "deadbeefdeadbeef",
                "reasoning": "Looks convincing.",
            }
        ),
    )
    breaker.review_alarm(aid)

    a = breaker.get_alarm(aid)
    assert a["status"] == "REJECTED"
    assert "nonce" in a["reasoning"]
    t = breaker.get_target(tid)
    assert t["status"] == "LIVE"


def test_review_twice_rejected(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce)
    breaker.review_alarm(aid)
    with pytest.raises(Exception, match="not awaiting"):
        breaker.review_alarm(aid)


def test_unreachable_review_is_recorded_not_settled(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    _mock_unreachable(direct_vm)
    breaker.review_alarm(aid)

    a = breaker.get_alarm(aid)
    assert a["status"] == "PENDING"
    assert int(a["failed_attempts"]) == 1
    t = breaker.get_target(tid)
    assert t["status"] == "LIVE"
    stats = breaker.get_stats()
    assert int(stats["total_bonds"]) == BOND


def test_retry_window_blocks_and_reopens(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    _mock_unreachable(direct_vm)
    breaker.review_alarm(aid)

    with pytest.raises(Exception, match="retry window"):
        breaker.review_alarm(aid)

    set_time("2030-01-01T02:00:00Z")
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce)
    breaker.review_alarm(aid)
    assert breaker.get_alarm(aid)["status"] == "VALID"


def test_review_budget_expires_the_alarm(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    for hour in range(1, 4):
        set_time(f"2030-01-01T{hour:02d}:00:00Z")
        _mock_unreachable(direct_vm)
        breaker.review_alarm(aid)
    a = breaker.get_alarm(aid)
    assert a["status"] == "EXPIRED"
    t = breaker.get_target(tid)
    assert int(t["active_alarm_id"]) == 0
    stats = breaker.get_stats()
    # Expired alarm: the bond goes home, nothing burned.
    assert int(stats["total_bonds"]) == 0
    assert int(stats["total_bail"]) == BAIL


# -------------------------------------------------------------------- resume
def test_resume_with_accepted_fix(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce)
    breaker.review_alarm(aid)

    direct_vm.sender = direct_alice
    direct_vm.value = BOND
    set_time("2030-01-02T00:00:00Z")
    _mock_fix(direct_vm)
    breaker.resume(tid, FIX_URL, "Added the balance check back to withdraw")
    direct_vm.value = 0

    t = breaker.get_target(tid)
    assert t["status"] == "LIVE"
    stats = breaker.get_stats()
    assert int(stats["paused"]) == 0


def test_resume_rejected_without_fix_mock(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce)
    breaker.review_alarm(aid)

    set_time("2030-01-02T00:00:00Z")
    direct_vm.sender = direct_alice
    direct_vm.value = BOND
    with pytest.raises(Exception):
        breaker.resume(tid, FIX_URL, "no page served")
    direct_vm.value = 0
    assert breaker.get_target(tid)["status"] == "EXPLOITED"


def test_resume_only_by_owner(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce)
    breaker.review_alarm(aid)

    set_time("2030-01-02T00:00:00Z")
    direct_vm.sender = direct_bob
    direct_vm.value = BOND
    with pytest.raises(Exception, match="only the target owner"):
        breaker.resume(tid, FIX_URL, "not the owner")
    direct_vm.value = 0


def test_resume_wrong_bond_reverts(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce)
    breaker.review_alarm(aid)

    set_time("2030-01-02T00:00:00Z")
    direct_vm.sender = direct_alice
    direct_vm.value = BOND // 2
    with pytest.raises(Exception, match="carries the alarm bond"):
        breaker.resume(tid, FIX_URL, "half a bond")
    direct_vm.value = 0


def test_resume_on_live_target_reverts(breaker, direct_vm, direct_alice):
    tid = _register(breaker, direct_vm, direct_alice)
    direct_vm.sender = direct_alice
    direct_vm.value = BOND
    with pytest.raises(Exception, match="not paused"):
        breaker.resume(tid, FIX_URL, "nothing to fix")
    direct_vm.value = 0


# --------------------------------------------------------------------- close
def test_close_returns_bail(breaker, direct_vm, direct_alice):
    tid = _register(breaker, direct_vm, direct_alice)
    direct_vm.sender = direct_alice
    breaker.close_target(tid)
    t = breaker.get_target(tid)
    assert t["status"] == "CLOSED"
    stats = breaker.get_stats()
    assert int(stats["total_bail"]) == 0


def test_close_blocked_while_paused(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce)
    breaker.review_alarm(aid)

    direct_vm.sender = direct_alice
    with pytest.raises(Exception, match="resume the target before"):
        breaker.close_target(tid)


def test_close_blocked_with_open_alarm(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    _alarm(breaker, direct_vm, direct_bob, tid)
    direct_vm.sender = direct_alice
    with pytest.raises(Exception, match="settle the open alarm"):
        breaker.close_target(tid)


def test_review_nonce_reservation_is_stable_and_consumed(breaker, direct_vm, direct_alice, direct_bob):
    """The nonce handshake: reserve once, the value holds until a review runs.

    A report is written for one exact nonce. If the value drifted between
    reserving and reviewing, no page could ever be right, so the reservation
    must hold across reads and survive until a review consumes it.
    """
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)

    first = breaker.reserve_review_nonce(aid)
    assert first == breaker.reserve_review_nonce(aid), "reservation drifted"
    assert first == breaker.alarm_review_nonce(aid), "view disagrees with the reservation"

    _mock_exploit(direct_vm, str(first))
    breaker.review_alarm(aid)

    t = breaker.get_target(tid)
    assert t["status"] == "EXPLOITED"
    # A second reservation after the round derives the next value.
    second = breaker.reserve_review_nonce(aid)
    assert second != first, "the consumed nonce was not cleared"


def test_alarm_bond_below_minimum_reverts(breaker, direct_vm, direct_alice, direct_bob):
    """An underfunded alarm must not even open: the bond is what makes a
    false alarm expensive, so a reporter who sends less than the minimum is
    refused before an alarm id is burned."""
    tid = _register(breaker, direct_vm, direct_alice)
    direct_vm.sender = direct_bob
    direct_vm.value = BOND - 1
    with pytest.raises(Exception, match="bond must match"):
        breaker.file_alarm(tid, ALARM_URL, "cheaper exploit, same drain")
    direct_vm.value = 0
    # No alarm id was consumed and the target is still clean.
    stats = breaker.get_stats()
    assert int(stats["alarms"]) == 0
    t = breaker.get_target(tid)
    assert int(t["active_alarm_id"]) == 0


def test_close_only_by_owner(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    direct_vm.sender = direct_bob
    with pytest.raises(Exception, match="only the target owner"):
        breaker.close_target(tid)


# ------------------------------------------------------------- pause surface
def test_is_paused_only_matches_exploited(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice, addr_hex="0x" + "22" * 20)
    t = breaker.get_target(tid)
    addr = t["contract_addr"]
    assert breaker.is_paused(str(addr)) is False

    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce)
    breaker.review_alarm(aid)
    assert breaker.is_paused(str(addr)) is True


def test_is_paused_false_for_strangers(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice, addr_hex="0x" + "33" * 20)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce)
    breaker.review_alarm(aid)
    assert breaker.is_paused("0x" + "44" * 20) is False


# ----------------------------------------------------------------- the vault
def test_vault_gate_with_dummy_breaker(direct_vm, direct_deploy, direct_alice, direct_bob):
    """The vault's local side of the gate contract.

    Direct mode has two quirks that keep the live pause path off the table
    here: it cannot hold two deployed contracts at once, and every
    cross-contract view returns None. So this test pins what is genuinely
    local — the owner's halt outranking everything and the gate plumbing not
    crashing on a breaker pointer — while the real breaker-pauses-vault path
    is proven end to end on StudioNet.
    """
    # A stand-in breaker whose ``is_paused`` always answers True.
    pauser = direct_deploy("contracts/_vault_pauser.py")
    pausing_addr = str(pauser.address)
    _reset()

    direct_vm.sender = direct_alice
    direct_vm.value = 10**18
    vault = direct_deploy("contracts/safe_vault.py", pausing_addr)
    direct_vm.value = 0

    # The owner's own brake outranks everything, no breaker round-trip.
    direct_vm.sender = direct_alice
    vault.halt()
    assert vault.gate_status() == "halted"
    direct_vm.value = 10**18
    with pytest.raises(Exception, match="owner halted this vault"):
        vault.deposit()
    direct_vm.value = 0
    with pytest.raises(Exception, match="owner halted this vault"):
        vault.withdraw(1)

    # Resume, and the gate reads the breaker again. Direct mode answers None
    # (cross-view quirk), which the vault treats as clear — the plumbing must
    # not crash either way.
    vault.resume()
    status = vault.gate_status()
    assert status in ("clear", "paused")
    direct_vm.value = 10**18
    vault.deposit()
    direct_vm.value = 0
    stats = vault.vault_stats()
    assert int(stats["total_deposits"]) == 10**18
    assert stats["last_gate_check"] == "clear"