"""BreakGlass direct-mode tests: the breaker, its guards, and the vault gate.

Everything here runs in a local VM with mocked validators, so the
deterministic rule set is covered exhaustively: the registration consent
handshake, contract-bound reviews, stale-evidence rejection, fund
conservation per outcome, and the full arcs (exploit -> resume -> close,
rejected alarm -> close). The live cross-contract handshake and the real
consensus path are covered on StudioNet by the integration tests.

Direct mode executes one contract per VM and returns nothing for
cross-contract calls, so the two-sided handshake is exercised through a seam:
the tests stub the breaker's three cross-contract methods on the loaded
class. The stubs answer exactly what a consenting vault would, and the
unstubbed fail-closed path is tested too: with no stub, the real consent read
returns nothing and registration is refused.
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
ARCHIVE_BODY = "deployed source: def withdraw(self, amount): ..." 

ALICE_TARGET = "0x" + "11" * 20
BOB_TARGET = "0x" + "22" * 20
STRANGER_TARGET = "0x" + "33" * 20


def _reset():
    import genlayer.gl.genvm_contracts as gvc

    gvc.__known_contract__ = None  # the direct loader does not reset this


@pytest.fixture()
def breaker(direct_vm, direct_deploy):
    c = direct_deploy("contracts/break_glass.py")
    yield c
    _reset()


def _hex(a) -> str:
    """Canonical lowercase 0x hex for an Address, bytes, or hex-ish value."""
    if isinstance(a, (bytes, bytearray)) and len(a) == 20:
        return "0x" + bytes(a).hex()
    h = getattr(a, "as_hex", None)
    s = h if isinstance(h, str) else str(a)
    if s.startswith("addr#"):
        s = "0x" + s[5:]
    return s.lower()


def _real_class(breaker):
    """The loaded BreakGlass class behind the calldata proxy."""
    inst = object.__getattribute__(breaker, "_instance")
    return type(inst)


def _install_consent(breaker, answers, confirmed=None):
    """Stub the breaker's cross-contract consent read on the loaded class.

    ``answers`` maps canonical contract hex to the consent dict the vault's
    ``breakglass_registration`` view would return. Contracts missing from the
    map answer nothing, which the breaker treats as a refusal.
    """
    cls = _real_class(breaker)

    def consent_view(self, addr):
        return answers.get(_hex(addr))

    cls._consent_view = consent_view
    return None


def _consent_ok(owner) -> dict:
    """The consent dict a consenting vault returns for its owner.

    The pinned-breaker field is read from the live message context, so the
    stub always names the breaker under test.
    """
    import genlayer.gl as gl

    return {"breaker": gl.message.contract_address, "owner": owner, "registered": False}


def _register(breaker, vm, who, addr_hex=None, bail=BAIL, label="safe-vault", answers=None):
    """Register a target with its owner, consent pre-installed."""
    addr_hex = addr_hex or ALICE_TARGET
    if answers is None:
        answers = {addr_hex: _consent_ok(who)}
    _install_consent(breaker, answers)
    vm.sender = who
    vm.value = bail
    tid = int(breaker.register_target(addr_hex, label, ARCHIVE_URL))
    vm.value = 0
    return tid


def _alarm(breaker, vm, who, tid, url=ALARM_URL, reason="Withdrawal bypass via reentrancy", bond=BOND):
    vm.sender = who
    vm.value = bond
    aid = int(breaker.file_alarm(tid, url, reason))
    vm.value = 0
    return aid


def _mock_exploit(vm, nonce, contract, fix_hash="a1b2c3d4e5f60718"):
    page = json.dumps(
        {
            "report": "PoC: withdraw() drains another user's balance",
            "tx_trace": "0xabc123",
            "contract": contract,
            "audit_nonce": nonce,
        }
    )
    vm.mock_web(rf"https://report\.example/poc", {"status": 200, "body": page})
    vm.mock_web(rf"https://vault\.example/audit", {"status": 200, "body": ARCHIVE_BODY})
    vm.mock_llm(
        r".*emergency alarm.*",
        json.dumps(
            {
                "verdict": "EXPLOITED",
                "nonce": nonce,
                "contract": contract,
                "fix_hash": fix_hash,
                "reasoning": "The report shows a working drain with a trace.",
            }
        ),
    )


def _mock_unproven(vm, nonce, contract):
    page = json.dumps({"report": "I think there might be an issue someday", "audit_nonce": nonce})
    vm.mock_web(rf"https://report\.example/poc", {"status": 200, "body": page})
    vm.mock_web(rf"https://vault\.example/audit", {"status": 200, "body": ARCHIVE_BODY})
    vm.mock_llm(
        r".*emergency alarm.*",
        json.dumps(
            {
                "verdict": "UNPROVEN",
                "nonce": nonce,
                "contract": contract,
                "fix_hash": "",
                "reasoning": "The report describes a hypothetical, no working exploit.",
            }
        ),
    )


def _mock_wrong_contract(vm, nonce, contract):
    """The judge is convinced, but the report names another contract."""
    page = json.dumps(
        {
            "report": "PoC: full drain of some contract",
            "contract": "0x" + "99" * 20,
            "audit_nonce": nonce,
        }
    )
    vm.mock_web(rf"https://report\.example/poc", {"status": 200, "body": page})
    vm.mock_web(rf"https://vault\.example/audit", {"status": 200, "body": ARCHIVE_BODY})
    vm.mock_llm(
        r".*emergency alarm.*",
        json.dumps(
            {
                "verdict": "EXPLOITED",
                "nonce": nonce,
                "contract": "0x" + "99" * 20,
                "fix_hash": "beefbeefbeefbeef",
                "reasoning": "Looks convincing.",
            }
        ),
    )


def _mock_unreachable(vm):
    # The direct web mock returns any registered mock's body regardless of
    # status, so a dark page is simulated by leaving the URL unmocked.
    pass


def _mock_fix(vm, contract):
    page = json.dumps({"patch": "checks added to withdraw", "contract": contract, "diff": "-balance check"})
    vm.mock_web(rf"https://patch\.example/fix", {"status": 200, "body": page})
    vm.mock_llm(
        r".*verifying a fix.*",
        json.dumps(
            {
                "verdict": "FIXED",
                "contract": contract,
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
    assert _hex(t["contract_addr"]) == ALICE_TARGET
    stats = breaker.get_stats()
    assert int(stats["total_bail"]) == BAIL
    assert int(stats["total_bail_in"]) == BAIL
    assert int(stats["live"]) == 1


def test_register_reverts_below_min_bail(breaker, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = BAIL // 2
    with pytest.raises(Exception, match="bail is below"):
        breaker.register_target(ALICE_TARGET, "v", ARCHIVE_URL)
    direct_vm.value = 0


@pytest.mark.parametrize("url", ["ftp://x.example/a", "not a url", ""])
def test_register_reverts_bad_url(breaker, direct_vm, direct_alice, url):
    direct_vm.sender = direct_alice
    direct_vm.value = BAIL
    with pytest.raises(Exception):
        breaker.register_target(ALICE_TARGET, "v", url)
    direct_vm.value = 0


def test_register_reverts_bad_label(breaker, direct_vm, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = BAIL
    with pytest.raises(Exception, match="label"):
        breaker.register_target(ALICE_TARGET, "", ARCHIVE_URL)
    direct_vm.value = 0


# ------------------------------------------------- the registration consent
def test_registration_refused_without_consent(breaker, direct_vm, direct_alice):
    """No stub installed: the real consent read returns nothing, fail-closed."""
    direct_vm.sender = direct_alice
    direct_vm.value = BAIL
    with pytest.raises(Exception, match="consent handshake"):
        breaker.register_target(ALICE_TARGET, "v", ARCHIVE_URL)
    direct_vm.value = 0
    stats = breaker.get_stats()
    assert int(stats["targets"]) == 0
    assert int(stats["total_bail"]) == 0


def test_registration_only_by_contract_owner(breaker, direct_vm, direct_alice, direct_bob):
    """Bob stakes the bail for a contract he does not own: refused."""
    answers = {ALICE_TARGET: _consent_ok(direct_alice)}
    _install_consent(breaker, answers)
    direct_vm.sender = direct_bob
    direct_vm.value = BAIL
    with pytest.raises(Exception, match="own owner"):
        breaker.register_target(ALICE_TARGET, "v", ARCHIVE_URL)
    direct_vm.value = 0
    assert int(breaker.get_stats()["targets"]) == 0


def test_registration_refused_when_breaker_not_pinned(breaker, direct_vm, direct_alice):
    """The contract pins another breaker: this breaker must refuse it."""
    answers = {
        ALICE_TARGET: {
            "breaker": "0x" + "77" * 20,
            "owner": direct_alice,
            "registered": False,
        }
    }
    _install_consent(breaker, answers)
    direct_vm.sender = direct_alice
    direct_vm.value = BAIL
    with pytest.raises(Exception, match="not pinned"):
        breaker.register_target(ALICE_TARGET, "v", ARCHIVE_URL)
    direct_vm.value = 0


def test_vault_local_flag_does_not_block_registration(breaker, direct_vm, direct_alice):
    """The vault's local gate flag is informational: the breaker's own
    registry, not the vault's switch, decides who is already protected."""
    answers = {ALICE_TARGET: _consent_ok(direct_alice)}
    answers[ALICE_TARGET]["registered"] = True
    _install_consent(breaker, answers)
    direct_vm.sender = direct_alice
    direct_vm.value = BAIL
    tid = int(breaker.register_target(ALICE_TARGET, "v", ARCHIVE_URL))
    direct_vm.value = 0
    assert breaker.get_target(tid)["status"] == "LIVE"


def test_duplicate_registration_refused(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    # A second registration of the same contract, even by another wallet
    # with otherwise valid consent, is refused.
    answers = {ALICE_TARGET: _consent_ok(direct_bob)}
    _install_consent(breaker, answers)
    direct_vm.sender = direct_bob
    direct_vm.value = BAIL
    with pytest.raises(Exception, match="already registered"):
        breaker.register_target(ALICE_TARGET, "copy", ARCHIVE_URL)
    direct_vm.value = 0
    stats = breaker.get_stats()
    assert int(stats["targets"]) == 1
    assert int(stats["total_bail"]) == BAIL


def test_breaker_cannot_protect_itself(breaker, direct_vm, direct_alice):
    self_addr = str(breaker.address)
    answers = {self_addr.lower(): _consent_ok(direct_alice)}
    _install_consent(breaker, answers)
    direct_vm.sender = direct_alice
    direct_vm.value = BAIL
    with pytest.raises(Exception, match="cannot protect itself"):
        breaker.register_target(self_addr, "self", ARCHIVE_URL)
    direct_vm.value = 0


def test_closed_registration_can_be_renewed(breaker, direct_vm, direct_alice):
    """Close returns the bail and frees the contract address; a fresh
    registration of the same contract is accepted again."""
    tid = _register(breaker, direct_vm, direct_alice)
    direct_vm.sender = direct_alice
    breaker.close_target(tid)

    tid2 = _register(breaker, direct_vm, direct_alice)
    assert int(tid2) == tid + 1
    stats = breaker.get_stats()
    assert int(stats["targets"]) == 2
    assert int(stats["closed"]) == 1
    assert int(stats["live"]) == 1
    assert int(stats["total_bail"]) == BAIL


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
    assert int(stats["total_bonds_in"]) == BOND


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
    _mock_exploit(direct_vm, nonce, ALICE_TARGET)
    breaker.review_alarm(aid)
    direct_vm.sender = direct_charlie
    direct_vm.value = BOND
    with pytest.raises(Exception, match="only accepted on a live"):
        breaker.file_alarm(tid, ALARM_URL, "second alarm on paused")
    direct_vm.value = 0


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


# ------------------------------------------------------------------- review
def test_valid_alarm_pauses_pays_reward_returns_bond(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce, ALICE_TARGET)
    breaker.review_alarm(aid)

    a = breaker.get_alarm(aid)
    assert a["status"] == "VALID"
    assert a["verdict"] == "EXPLOITED"
    t = breaker.get_target(tid)
    assert t["status"] == "EXPLOITED"
    assert t["last_fix_hash"] == "a1b2c3d4e5f60718"

    stats = breaker.get_stats()
    # The reward comes out of the bail; the reporter's bond goes home on top.
    assert int(stats["total_bail"]) == BAIL - REWARD
    assert int(stats["total_bail_out"]) == REWARD
    assert int(stats["total_bonds"]) == 0
    assert int(stats["total_bonds_out"]) == BOND
    assert int(stats["total_paid"]) == REWARD
    assert int(stats["paused"]) == 1
    assert stats["bail_consistent"] is True
    assert stats["bonds_consistent"] is True


def test_unproven_alarm_burns_bond_into_bail(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_unproven(direct_vm, nonce, ALICE_TARGET)
    breaker.review_alarm(aid)

    a = breaker.get_alarm(aid)
    assert a["status"] == "REJECTED"
    t = breaker.get_target(tid)
    assert t["status"] == "LIVE"
    stats = breaker.get_stats()
    # The reporter's bond burned into the bail.
    assert int(stats["total_bail"]) == BAIL + BOND
    assert int(stats["total_bail_in"]) == BAIL + BOND
    assert int(stats["total_burned"]) == BOND
    assert int(stats["total_bonds"]) == 0
    assert int(stats["total_bonds_out"]) == 0
    assert int(stats["total_paid"]) == 0
    assert stats["bail_consistent"] is True
    assert stats["bonds_consistent"] is True


def test_report_not_bound_to_registered_contract_is_rejected(breaker, direct_vm, direct_alice, direct_bob):
    """A convincing report about another contract proves nothing here."""
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_wrong_contract(direct_vm, nonce, ALICE_TARGET)
    breaker.review_alarm(aid)

    a = breaker.get_alarm(aid)
    assert a["status"] == "REJECTED"
    assert "does not bind" in a["reasoning"]
    t = breaker.get_target(tid)
    assert t["status"] == "LIVE"
    stats = breaker.get_stats()
    assert int(stats["total_burned"]) == BOND
    assert int(stats["total_paid"]) == 0


def test_nonceless_report_falsifies_even_with_perfect_content(breaker, direct_vm, direct_alice, direct_bob):
    """The frozen-page attack: a perfect report written before the alarm."""
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)

    page = json.dumps({"report": "PoC: full drain", "contract": ALICE_TARGET, "audit_nonce": "0" * 32})
    direct_vm.mock_web(rf"https://report\.example/poc", {"status": 200, "body": page})
    direct_vm.mock_web(rf"https://vault\.example/audit", {"status": 200, "body": ARCHIVE_BODY})
    # The judge says EXPLOITED with a stale nonce: the contract must override.
    direct_vm.mock_llm(
        r".*emergency alarm.*",
        json.dumps(
            {
                "verdict": "EXPLOITED",
                "nonce": "0" * 32,
                "contract": ALICE_TARGET,
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


def test_stale_exploit_hash_is_rejected_after_a_fix(breaker, direct_vm, direct_alice, direct_bob):
    """Alarm 2 naming the fixed code is stale evidence, not a live exploit."""
    tid = _register(breaker, direct_vm, direct_alice)

    # Round 1: a real exploit with hash H is confirmed.
    aid1 = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce1 = breaker.alarm_review_nonce(aid1)
    _mock_exploit(direct_vm, nonce1, ALICE_TARGET, fix_hash="a1b2c3d4e5f60718")
    breaker.review_alarm(aid1)
    assert breaker.get_target(tid)["status"] == "EXPLOITED"
    direct_vm.clear_mocks()

    # The owner fixes it; the fix names the same hash.
    direct_vm.sender = direct_alice
    direct_vm.value = BOND
    set_time("2030-01-02T00:00:00Z")
    _mock_fix(direct_vm, ALICE_TARGET)
    breaker.resume(tid, FIX_URL, "Added the balance check back to withdraw")
    direct_vm.value = 0
    direct_vm.clear_mocks()

    t = breaker.get_target(tid)
    assert t["status"] == "LIVE"
    assert t["last_fix_hash"] == "a1b2c3d4e5f60718"

    # Round 2: the same hash is reported again, with a fresh page and nonce.
    aid2 = _alarm(breaker, direct_vm, direct_bob, tid, url="https://report.example/poc2")
    direct_vm.mock_web(rf"https://report\.example/poc2", {"status": 200, "body": "stale copy"})
    direct_vm.mock_web(rf"https://vault\.example/audit", {"status": 200, "body": ARCHIVE_BODY})
    nonce2 = breaker.alarm_review_nonce(aid2)
    direct_vm.mock_llm(
        r".*emergency alarm.*",
        json.dumps(
            {
                "verdict": "EXPLOITED",
                "nonce": nonce2,
                "contract": ALICE_TARGET,
                "fix_hash": "a1b2c3d4e5f60718",
                "reasoning": "Same drain, same code path.",
            }
        ),
    )
    breaker.review_alarm(aid2)

    a2 = breaker.get_alarm(aid2)
    assert a2["status"] == "REJECTED"
    assert "already fixed" in a2["reasoning"]
    assert breaker.get_target(tid)["status"] == "LIVE"
    stats = breaker.get_stats()
    # Round 1 paid the reward; round 2 burned its bond into the bail.
    assert int(stats["total_paid"]) == REWARD
    assert int(stats["total_burned"]) == BOND
    assert int(stats["total_bail"]) == BAIL - REWARD + BOND


def test_fresh_exploit_hash_after_a_fix_is_accepted(breaker, direct_vm, direct_alice, direct_bob):
    """A genuinely new exploit (new hash) is not blocked by the dedup."""
    tid = _register(breaker, direct_vm, direct_alice)
    aid1 = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce1 = breaker.alarm_review_nonce(aid1)
    _mock_exploit(direct_vm, nonce1, ALICE_TARGET, fix_hash="a1b2c3d4e5f60718")
    breaker.review_alarm(aid1)
    direct_vm.clear_mocks()

    direct_vm.sender = direct_alice
    direct_vm.value = BOND
    set_time("2030-01-02T00:00:00Z")
    _mock_fix(direct_vm, ALICE_TARGET)
    breaker.resume(tid, FIX_URL, "Fixed the first drain")
    direct_vm.value = 0
    direct_vm.clear_mocks()

    aid2 = _alarm(breaker, direct_vm, direct_bob, tid, url="https://report.example/poc2")
    nonce2 = breaker.alarm_review_nonce(aid2)
    _mock_exploit(direct_vm, nonce2, ALICE_TARGET, fix_hash="0f0f0f0f0f0f0f0f")
    breaker.review_alarm(aid2)
    a2 = breaker.get_alarm(aid2)
    assert a2["status"] == "VALID"
    assert breaker.get_target(tid)["status"] == "EXPLOITED"


def test_review_twice_rejected(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce, ALICE_TARGET)
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
    _mock_exploit(direct_vm, nonce, ALICE_TARGET)
    breaker.review_alarm(aid)
    assert breaker.get_alarm(aid)["status"] == "VALID"


def test_review_budget_expires_the_alarm_and_refunds_the_bond(breaker, direct_vm, direct_alice, direct_bob):
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
    assert int(stats["total_bonds_out"]) == BOND
    assert int(stats["total_bail"]) == BAIL
    assert stats["bonds_consistent"] is True


# -------------------------------------------------------------------- resume
def test_resume_with_accepted_fix(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce, ALICE_TARGET)
    breaker.review_alarm(aid)

    direct_vm.sender = direct_alice
    direct_vm.value = BOND
    set_time("2030-01-02T00:00:00Z")
    _mock_fix(direct_vm, ALICE_TARGET)
    breaker.resume(tid, FIX_URL, "Added the balance check back to withdraw")
    direct_vm.value = 0

    t = breaker.get_target(tid)
    assert t["status"] == "LIVE"
    stats = breaker.get_stats()
    assert int(stats["paused"]) == 0
    # The resume stake came back to the owner.
    assert int(stats["total_bonds"]) == 0
    assert int(stats["total_bonds_out"]) == BOND + BOND  # alarm bond + resume stake


def test_resume_rejected_without_fix_mock(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce, ALICE_TARGET)
    breaker.review_alarm(aid)

    set_time("2030-01-02T00:00:00Z")
    direct_vm.sender = direct_alice
    direct_vm.value = BOND
    with pytest.raises(Exception):
        breaker.resume(tid, FIX_URL, "no page served")
    direct_vm.value = 0
    assert breaker.get_target(tid)["status"] == "EXPLOITED"


def test_resume_fix_not_bound_to_contract_reverts(breaker, direct_vm, direct_alice, direct_bob):
    """A fix page about another contract does not lift this pause."""
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce, ALICE_TARGET)
    breaker.review_alarm(aid)

    set_time("2030-01-02T00:00:00Z")
    direct_vm.sender = direct_alice
    direct_vm.value = BOND
    page = json.dumps({"patch": "checks added", "contract": "0x" + "99" * 20, "diff": "-x"})
    direct_vm.mock_web(rf"https://patch\.example/fix", {"status": 200, "body": page})
    direct_vm.mock_llm(
        r".*verifying a fix.*",
        json.dumps(
            {
                "verdict": "FIXED",
                "contract": "0x" + "99" * 20,
                "fix_hash": "a1b2c3d4e5f60718",
                "reasoning": "A real fix, but for another contract.",
            }
        ),
    )
    with pytest.raises(Exception, match="does not bind"):
        breaker.resume(tid, FIX_URL, "points at someone else's patch")
    direct_vm.value = 0
    assert breaker.get_target(tid)["status"] == "EXPLOITED"


def test_resume_only_by_owner(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce, ALICE_TARGET)
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
    _mock_exploit(direct_vm, nonce, ALICE_TARGET)
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
    assert int(stats["total_bail_out"]) == BAIL


def test_close_blocked_while_paused(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce, ALICE_TARGET)
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


def test_close_only_by_owner(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice)
    direct_vm.sender = direct_bob
    with pytest.raises(Exception, match="only the target owner"):
        breaker.close_target(tid)


# ------------------------------------------------------------- the full arcs
def test_arc_exploit_resume_close(breaker, direct_vm, direct_alice, direct_bob):
    """Exploit -> resume -> close: every wei accounted for at the end.

    Bail in, reward out to the reporter, alarm bond back to the reporter,
    resume stake back to the owner, remaining bail home to the owner. Held
    funds end at zero and the lifetime flows reconcile.
    """
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce, ALICE_TARGET)
    breaker.review_alarm(aid)

    direct_vm.sender = direct_alice
    direct_vm.value = BOND
    set_time("2030-01-02T00:00:00Z")
    _mock_fix(direct_vm, ALICE_TARGET)
    breaker.resume(tid, FIX_URL, "The fix that holds")
    direct_vm.value = 0

    direct_vm.sender = direct_alice
    breaker.close_target(tid)

    t = breaker.get_target(tid)
    assert t["status"] == "CLOSED"
    stats = breaker.get_stats()
    assert int(stats["total_bail"]) == 0
    assert int(stats["total_bonds"]) == 0
    # Bail: in BAIL, out REWARD (reward) + (BAIL - REWARD) (close refund).
    assert int(stats["total_bail_in"]) == BAIL
    assert int(stats["total_bail_out"]) == BAIL
    # Bonds: in BOND (alarm) + BOND (resume stake), out the same, all to wallets.
    assert int(stats["total_bonds_in"]) == BOND + BOND
    assert int(stats["total_bonds_out"]) == BOND + BOND
    assert int(stats["total_paid"]) == REWARD
    assert int(stats["total_burned"]) == 0
    assert stats["bail_consistent"] is True
    assert stats["bonds_consistent"] is True


def test_arc_rejected_alarm_close(breaker, direct_vm, direct_alice, direct_bob):
    """Rejected alarm -> close: the burned bond goes home with the bail.

    The false reporter's bond grows the target's insurance pool, so the
    owner closes with bail + bond and the held totals still land at zero.
    """
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_unproven(direct_vm, nonce, ALICE_TARGET)
    breaker.review_alarm(aid)
    assert breaker.get_alarm(aid)["status"] == "REJECTED"

    direct_vm.sender = direct_alice
    breaker.close_target(tid)

    t = breaker.get_target(tid)
    assert t["status"] == "CLOSED"
    stats = breaker.get_stats()
    assert int(stats["total_bail"]) == 0
    assert int(stats["total_bonds"]) == 0
    # The close refund carries the burned bond home to the owner.
    assert int(stats["total_bail_in"]) == BAIL + BOND
    assert int(stats["total_bail_out"]) == BAIL + BOND
    assert int(stats["total_bonds_in"]) == BOND
    assert int(stats["total_bonds_out"]) == 0
    assert int(stats["total_burned"]) == BOND
    assert int(stats["total_paid"]) == 0
    assert stats["bail_consistent"] is True
    assert stats["bonds_consistent"] is True


def test_arc_expired_alarm_close(breaker, direct_vm, direct_alice, direct_bob):
    """Expired alarm -> close: the bond went home, the bail follows."""
    tid = _register(breaker, direct_vm, direct_alice)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    for hour in range(1, 4):
        set_time(f"2030-01-01T{hour:02d}:00:00Z")
        _mock_unreachable(direct_vm)
        breaker.review_alarm(aid)
    assert breaker.get_alarm(aid)["status"] == "EXPIRED"

    direct_vm.sender = direct_alice
    breaker.close_target(tid)

    stats = breaker.get_stats()
    assert int(stats["total_bail"]) == 0
    assert int(stats["total_bonds"]) == 0
    assert int(stats["total_bail_in"]) == BAIL
    assert int(stats["total_bail_out"]) == BAIL
    assert int(stats["total_bonds_in"]) == BOND
    assert int(stats["total_bonds_out"]) == BOND
    assert int(stats["total_burned"]) == 0
    assert int(stats["total_paid"]) == 0


# ------------------------------------------------------------- nonce surface
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

    _mock_exploit(direct_vm, str(first), ALICE_TARGET)
    breaker.review_alarm(aid)

    t = breaker.get_target(tid)
    assert t["status"] == "EXPLOITED"
    # A second reservation after the round derives the next value.
    second = breaker.reserve_review_nonce(aid)
    assert second != first, "the consumed nonce was not cleared"


# ------------------------------------------------------------- pause surface
def test_is_paused_only_matches_exploited(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice, addr_hex=BOB_TARGET)
    t = breaker.get_target(tid)
    addr = t["contract_addr"]
    assert breaker.is_paused(str(addr)) is False

    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce, BOB_TARGET)
    breaker.review_alarm(aid)
    assert breaker.is_paused(str(addr)) is True


def test_is_paused_false_for_strangers(breaker, direct_vm, direct_alice, direct_bob):
    tid = _register(breaker, direct_vm, direct_alice, addr_hex=STRANGER_TARGET)
    aid = _alarm(breaker, direct_vm, direct_bob, tid)
    nonce = breaker.alarm_review_nonce(aid)
    _mock_exploit(direct_vm, nonce, STRANGER_TARGET)
    breaker.review_alarm(aid)
    assert breaker.is_paused("0x" + "44" * 20) is False


# ----------------------------------------------------------------- the vault
def test_vault_consent_view_and_gate_switch(direct_vm, direct_deploy, direct_alice, direct_bob):
    """The vault's consent view names the pinned breaker and its owner, and
    only the owner flips the local gate switch."""
    pauser = direct_deploy("contracts/_vault_pauser.py")
    pausing_addr = str(pauser.address)
    _reset()

    direct_vm.sender = direct_alice
    direct_vm.value = 10**18
    vault = direct_deploy("contracts/safe_vault.py", pausing_addr)
    direct_vm.value = 0

    # The consent view reports the pinned breaker and the registration state.
    info = vault.breakglass_registration()
    assert _hex(info["breaker"]) == pausing_addr.lower()
    assert bool(info["registered"]) is False
    assert _hex(info["owner"]) == _hex(direct_alice)

    # A stranger cannot flip the gate; the owner can.
    direct_vm.sender = direct_bob
    with pytest.raises(Exception, match="only the owner"):
        vault.arm_gate(True)
    direct_vm.sender = direct_alice
    vault.arm_gate(True)
    assert int(vault.vault_stats()["registration_open"]) == 1
    vault.arm_gate(False)
    assert int(vault.vault_stats()["registration_open"]) == 0


def test_vault_gate_with_dummy_breaker(direct_vm, direct_deploy, direct_alice, direct_bob):
    """The vault's local side of the gate contract.

    Direct mode has two quirks that keep the live pause path off the table
    here: it cannot hold two deployed contracts at once, and every
    cross-contract view returns None. So this test pins what is genuinely
    local (the owner's halt outranking everything and the gate plumbing not
    crashing on a breaker pointer), while the real breaker-pauses-vault path
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
