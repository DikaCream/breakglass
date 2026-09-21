"""Integration tests for BreakGlass on StudioNet.

Run: gltest --network studionet tests/integration/test_break_glass.py -v -s

These exercise the real consensus path: validators fetch a live public report
page, agree on the verdict through the comparative equivalence principle, and
the accepted verdict pauses a real second contract. The report endpoints here
are rewritten per run through a public host, because the report must carry the
review nonce that only exists after the alarm is filed. The deterministic rule
set and every rejection path are covered by the direct-mode tests.
"""

import json
import time
import urllib.request

import pytest
from gltest import get_accounts, get_contract_factory
from gltest.assertions import tx_execution_succeeded, tx_execution_failed

GEN = 10**18
BAIL = GEN // 10        # 0.1 GEN minimum
BOND = GEN // 100       # 0.01 GEN alarm bond
REWARD = BAIL // 4      # an accepted alarm pays a quarter of the bail

REPORT = (
    "PoC: withdraw() drains another user's balance. Attack trace attached. "
    "The exploit moves funds without authority and reproduces on the live "
    "contract."
)
FIX_NOTE = "Patched the reentrancy guard and redeployed the contract."

# A concrete, self-contained exploit report: the vulnerable code, a step by
# step reproduction against the live contract, and the observed balance
# diff. The validators read the page as text and must judge it as a real,
# live exploit, so placeholder traces do not survive consensus.
EXPLOIT_PAGE = """EXPLOIT REPORT - safe-vault - unauthorized withdrawal

VULNERABLE FUNCTION (deployed source, function withdraw):

    def withdraw(self, amount: u256) -> None:
        to = gl.message.sender_address
        cur = int(self.balances.get(to, u256(0)))
        if int(amount) <= 0 or int(amount) > cur:
            raise gl.vm.UserError("withdraw more than your balance")
        # BUG: the external transfer fires BEFORE the storage update.
        gl.emit_transfer(to, value=u256(int(amount)))
        self.balances[to] = u256(cur - int(amount))

The external call happens before the balance decrement. During the transfer
callback the attacker re-enters withdraw(): the storage read still returns
the full stale balance, so one deposit can be withdrawn many times.

TRANSACTION TRACE (reproduction run against the live contract):

  Pre-state:  vault holds 2 GEN (alice deposited 1 GEN, attacker deposited 1 GEN)

  tx_hash:        0x7c9e31a4f0b8d2e65a1c4f7b9d0e3a5c8f2b6d1e94a7c3f0b5d8e2a6c4f19b73
  block:          48213
  status:         ACCEPTED (executed)
  from:           0x91fE0f4aD83b726c19d4A62e5F8c3ba0dE17c954 (attacker)
  to:             0x4592034d6971EC6EB4cc272497E120B28C796C81 (safe-vault)
  selector:       withdraw(uint256) = 0x2e1a7d4d
  calldata (hex): 0x2e1a7d4d0000000000000000000000000000000000000000000000000de0b6b3a7640000

  frame 1  withdraw(1 GEN)     attacker storage balance 1 GEN -> check passes
  |  frame 2    gl.emit_transfer(1 GEN) -> external transfer, reentrant callback
  |  |  frame 3 withdraw(1 GEN)   storage STILL reads 1 GEN (decrement not yet
  |  |  |                         written) -> the same balance passes again
  |  |  |  frame 4 gl.emit_transfer(1 GEN) -> 1 GEN leaves the vault a 2nd time
  |  |  frame 3 returns           frame 3 writes attacker balance 1-1 = 0
  |  frame 1 returns              frame 1 writes attacker balance 1-1 = 0 again

RECEIPT LOGS (emitted by the two emit_transfer calls above):

  log 0: Transfer(from=0x4592...C81 (safe-vault), to=0x91fE...c954 (attacker), value=1000000000000000000)
  log 1: Transfer(from=0x4592...C81 (safe-vault), to=0x91fE...c954 (attacker), value=1000000000000000000)

OBSERVED STATE CHANGE (read from storage after the run):

  vault total_deposits: 2 GEN  ->  0 GEN  (drained)
  attacker (books):     1 GEN  ->  0 GEN  (decremented once, withdrawn twice)
  attacker (wallet):    1 GEN  ->  3 GEN  (deposit back + two 1 GEN transfers)
  alice (books):        1 GEN  ->  1 GEN  (unbacked: the vault is empty)

Two transfers of 1 GEN each left the vault against 1 GEN of the attacker's
own balance. Alice's 1 GEN is still on the books with nothing behind it.
The withdrawal of funds without the owner's authority is reproduced on the
deployed contract.
"""


def _new_webhook_url() -> str:
    """Create an empty page slot on a public host whose content can be
    rewritten through its API, and return its URL."""
    req = urllib.request.Request(
        "https://webhook.site/token",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    token = json.loads(urllib.request.urlopen(req, timeout=30).read())["uuid"]
    return f"https://webhook.site/{token}"


def _write_page(url: str, body: str) -> None:
    token = url.rsplit("/", 1)[1]
    req = urllib.request.Request(
        f"https://webhook.site/token/{token}",
        data=json.dumps({"default_content": body, "status": 200}).encode(),
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    urllib.request.urlopen(req, timeout=30)
    served = urllib.request.urlopen(url, timeout=30).read().decode()
    assert body in served, "the endpoint did not take the new content"


def _deploy(account):
    factory = get_contract_factory("BreakGlass")
    return factory.deploy(account=account)


def _register(breaker, account, vault_addr_hex):
    receipt = (
        breaker.connect(account)
        .register_target(args=[vault_addr_hex, "safe-vault", "https://example.com/archive"])
        .transact(value=BAIL, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    stats = breaker.get_stats(args=[]).call()
    return int(stats["targets"])


def _file_alarm(breaker, account, tid):
    url = _new_webhook_url()
    receipt = (
        breaker.connect(account)
        .file_alarm(args=[tid, url, REPORT])
        .transact(value=BOND, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    stats = breaker.get_stats(args=[]).call()
    return int(stats["alarms"]), url


def _publish_report(breaker, url, aid, account):
    """Reserve the review nonce on-chain, then write the report for it."""
    receipt = (
        breaker.connect(account)
        .reserve_review_nonce(args=[aid])
        .transact(wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    nonce = str(breaker.alarm_review_nonce(args=[aid]).call())
    _write_page(url, EXPLOIT_PAGE + f"\nAUDIT NONCE: {nonce}\n")
    return nonce


@pytest.mark.integration
def test_alarm_pauses_real_vault_then_fix_resumes():
    """The full arc: alarm -> consensus verdict -> vault paused -> fix -> live.

    The vault here is a real second contract whose money movement consults
    the breaker's verdict. This is the pull-model gate the direct mode could
    not prove: two live contracts on the real network.
    """
    accounts = get_accounts()
    owner, reporter = accounts[0], accounts[1]

    # Deploy the breaker, then the protected vault pointed at it.
    breaker = _deploy(owner)
    vault_factory = get_contract_factory("SafeVault")
    vault = vault_factory.deploy(args=[str(breaker.address)], account=owner)

    # Owner funds the vault. Money moves while no alarm stands.
    receipt = (
        vault.connect(owner)
        .deposit(args=[])
        .transact(value=GEN, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)

    tid = _register(breaker, owner, str(vault.address))

    # A third party stakes the bond and files the alarm.
    aid, url = _file_alarm(breaker, reporter, tid)

    # Publish the exploit report written for this review's nonce.
    _publish_report(breaker, url, aid, reporter)

    receipt = (
        breaker.review_alarm(args=[aid])
        .transact(wait_interval=10000, wait_retries=25)
    )
    assert tx_execution_succeeded(receipt)

    t = breaker.get_target(args=[tid]).call()
    a = breaker.get_alarm(args=[aid]).call()
    print(f"\n[diag] alarm status={a['status']} verdict={a['verdict']}")
    print(f"[diag] reasoning={str(a['reasoning'])[:400]}")
    assert t["status"] == "EXPLOITED", f"expected the vault paused, got {t['status']}"

    # The pause check reads True for the vault's address.
    assert breaker.is_paused(args=[str(vault.address)]).call() is True

    # The gate: the vault itself now refuses to move money. A reverted write
    # still "succeeds" as a transaction, so the check is on the execution
    # result, not on an exception.
    receipt = (
        vault.connect(owner)
        .deposit(args=[])
        .transact(value=GEN, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_failed(receipt), "deposit went through while the target is EXPLOITED"
    # A reverted write rolls its storage back entirely, so the vault's totals
    # must be untouched: nothing moved while the pause stood.
    stats = vault.vault_stats(args=[]).call()
    assert int(stats["total_deposits"]) == GEN, "a blocked deposit changed the vault"
    assert vault.gate_status().call() == "paused"

    # The reporter collects a quarter of the bail.
    stats = breaker.get_stats(args=[]).call()
    assert int(stats["total_paid"]) == REWARD

    # The owner publishes a fix and stakes the resume bond.
    fix_url = _new_webhook_url()
    _write_page(
        fix_url,
        "Fix: reentrancy guard added to withdraw(); redeployed at "
        "commit 9f83ab1. Diff and deployment record included.",
    )
    receipt = (
        breaker.connect(owner)
        .resume(args=[tid, fix_url, FIX_NOTE])
        .transact(value=BOND, wait_interval=10000, wait_retries=25)
    )
    assert tx_execution_succeeded(receipt)

    t = breaker.get_target(args=[tid]).call()
    assert t["status"] == "LIVE", f"expected the vault resumed, got {t['status']}"

    # Money moves again.
    receipt = (
        vault.connect(owner)
        .deposit(args=[])
        .transact(value=GEN, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)


@pytest.mark.integration
def test_stale_report_without_nonce_is_unproven():
    """A report page from the past proves nothing.

    The page below predates the review's nonce (the host page never carries
    it), so the code-level echo check must downgrade the verdict to UNPROVEN
    even if the model itself is convinced by the prose.
    """
    accounts = get_accounts()
    owner, reporter = accounts[0], accounts[1]

    breaker = _deploy(owner)
    tid = _register(breaker, owner, "0x" + "77" * 20)
    aid, url = _file_alarm(breaker, reporter, tid)

    # A report with no nonce at all: written before the alarm existed.
    _write_page(
        url,
        json.dumps(
            {
                "report": REPORT,
                "tx_trace": "0xdeadbeef",
                "audit_nonce": "",
            }
        ),
    )

    receipt = breaker.review_alarm(args=[aid]).transact(
        wait_interval=10000, wait_retries=25
    )
    assert tx_execution_succeeded(receipt)

    a = breaker.get_alarm(args=[aid]).call()
    assert a["status"] == "REJECTED", f"stale report must not pass, got {a['status']}"

    # A false alarm burns the bond into the target's bail.
    t = breaker.get_target(args=[tid]).call()
    assert t["status"] == "LIVE"
    stats = breaker.get_stats(args=[]).call()
    assert int(stats["total_paid"]) == 0


@pytest.mark.integration
def test_unreachable_report_fails_and_gates_retries():
    """A dead report URL burns a review attempt, keeps the alarm open, and
    the one-hour cooldown gates the next run on the live clock."""
    accounts = get_accounts()
    owner, reporter = accounts[0], accounts[1]

    breaker = _deploy(owner)
    tid = _register(breaker, owner, "0x" + "88" * 20)

    url = "https://no-such-report-endpoint-a1b2c3d4.invalid/report"
    receipt = (
        breaker.connect(reporter)
        .file_alarm(args=[tid, url, REPORT])
        .transact(value=BOND, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    aid = int(breaker.get_stats(args=[]).call()["alarms"])

    # One failed round proves the attempt is recorded and the alarm stays
    # open. The budget-exhaustion path (each retry gated by the one-hour
    # cooldown) is covered by the direct tests, which control the clock.
    receipt = breaker.review_alarm(args=[aid]).transact(
        wait_interval=10000, wait_retries=25
    )
    assert tx_execution_succeeded(receipt)

    a = breaker.get_alarm(args=[aid]).call()
    assert a["status"] == "PENDING", "a failed round must keep the alarm open"
    assert int(a["failed_attempts"]) == 1
    t = breaker.get_target(args=[tid]).call()
    assert t["status"] == "LIVE"

    # The retry window is the cooldown past that attempt; prove the gate
    # exists on the live clock.
    receipt = breaker.review_alarm(args=[aid]).transact(
        wait_interval=10000, wait_retries=15
    )
    assert tx_execution_failed(receipt), "the retry window did not gate the re-run"

    # The bond is untouched while the alarm awaits its remaining budget.
    stats = breaker.get_stats(args=[]).call()
    assert int(stats["total_bonds"]) == BOND
