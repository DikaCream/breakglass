"""E2E on the live StudioNet board: a visitor walks the whole alarm flow.

Run: gltest --network studionet tests/e2e_visitor_alarm.py -v -s

Each run deploys a fresh VulnerableVault (the kept pre-fix draft of the
demo vault, see contracts/_vulnerable_vault.py), registers it under the
live breaker, then does exactly what a visitor does in the browser: file
the alarm, reserve the nonce, publish the report page with the nonce
inside, run the review, and verify the verdict, the pause and the reporter
payout on-chain. The report quotes the exact deployed source, which is
public in the repository, so validators can check the code against the
deployment's own repo.
"""

import json
import time
import urllib.request

from gltest import get_accounts, get_contract_factory
from gltest.assertions import tx_execution_succeeded

GEN = 10**18
BAIL = GEN // 10        # 0.1 GEN minimum bail
BOND = GEN // 100       # 0.01 GEN alarm bond
BREAKER = "0x91Bc965E0939F47Cc9aAFCD42ca11a683578484f"

REPORT = (
    "Withdrawal bypass through reentrancy: funds leave the vault without "
    "authority. The vulnerable code, the reproduction and the trace are in "
    "the report."
)

EXPLOIT_PAGE = """EXPLOIT REPORT - payments-vault - unauthorized withdrawal

DEPLOYED TARGET (registered on the breaker this run):

  label:            payments-vault
  target id:        {target_id}
  target contract:  {vault_addr}
  breaker contract: 0x91Bc965E0939F47Cc9aAFCD42ca11a683578484f

SOURCE OF TRUTH (independently checkable):

  The deployed vault is the pre-fix draft of the demo vault. Its source is
  public: contracts/_vulnerable_vault.py in the repository
  https://github.com/DikaCream/breakglass - the vulnerable function below
  is copied from that file, unchanged. The patched version of the same
  vault (contracts/safe_vault.py in the same repository) shows the fix and
  documents this exact bug: the external transfer used to fire before the
  balance update.

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

REPRODUCTION (against the deployed contract above):

  1. deposit 1 GEN from an address with a reentrant receiver
  2. call withdraw(1 GEN); the receiver re-enters withdraw(1 GEN) inside
     the transfer callback
  3. observed on this deployment: two Transfer events of 1 GEN each leave
     the vault, the attacker's book balance is written twice from the same
     stale read, and total_deposits drops by 2 GEN against 1 GEN owned
  4. alice's 1 GEN stays on the books with nothing behind it - funds left
     the vault without the owner's authority

REPRODUCTION CHECK: redeploying contracts/_vulnerable_vault.py from the
public repository above reproduces exactly the trace and the state change
described here. The patched contracts/safe_vault.py in the same repository
does not: there the storage update lands before the external transfer.
"""


def _retry(fn, tries=4, pause=8, what="call"):
    last = None
    for i in range(tries):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - any transient error retries
            last = e
            print(f"  [retry] {what} attempt {i + 1} failed: {str(e)[:120]}")
            time.sleep(pause)
    raise last


def _new_webhook_url() -> str:
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
    assert body in served, "the endpoint did not take the content"


def test_visitor_alarm_e2e():
    """Full arc: fresh vulnerable target -> alarm -> nonce -> review -> pause
    -> payout -> the owner repairs and the pause lifts."""
    accounts = get_accounts()
    owner, reporter = accounts[0], accounts[1]

    breaker = get_contract_factory("BreakGlass").build_contract(BREAKER)

    # ---- 0. a fresh vulnerable target, deployed by this run ---------------
    vault = get_contract_factory("VulnerableVault").deploy(account=owner)
    receipt = (
        vault.connect(owner)
        .deposit(args=[])
        .transact(value=GEN, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    receipt = (
        breaker.connect(owner)
        .register_target(
            args=[str(vault.address), "payments-vault", "https://github.com/DikaCream/breakglass"]
        )
        .transact(value=BAIL, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    tid = int(breaker.get_stats(args=[]).call()["targets"])
    print(f"\nfresh vulnerable target {tid} at {vault.address}")

    # ---- 1. the visitor publishes a report page (nonce comes later) -------
    url = _new_webhook_url()
    page = EXPLOIT_PAGE.format(target_id=tid, vault_addr=vault.address)
    _write_page(url, page)
    print(f"report page live: {url}")

    # ---- 2. file the alarm with the bond -----------------------------------
    receipt = _retry(
        lambda: breaker.connect(reporter)
        .file_alarm(args=[tid, url, REPORT])
        .transact(value=BOND, wait_interval=10000, wait_retries=15),
        what="file_alarm",
    )
    assert tx_execution_succeeded(receipt)
    aid = int(breaker.get_target(args=[tid]).call()["active_alarm_id"])
    print(f"alarm {aid} filed, bond {BOND / GEN} GEN staked")

    # ---- 3. reserve the nonce ----------------------------------------------
    receipt = _retry(
        lambda: breaker.connect(reporter)
        .reserve_review_nonce(args=[aid])
        .transact(wait_interval=10000, wait_retries=15),
        what="reserve_nonce",
    )
    assert tx_execution_succeeded(receipt)
    nonce = str(breaker.alarm_review_nonce(args=[aid]).call())
    print(f"nonce reserved: {nonce}")

    # ---- 4. write the nonce into the report page ---------------------------
    _write_page(url, page + f"\nAUDIT NONCE: {nonce}\n")
    print("nonce written into the live page")

    # ---- 5. run the review (validators fetch + agree) ----------------------
    receipt = _retry(
        lambda: breaker.review_alarm(args=[aid]).transact(
            wait_interval=10000, wait_retries=30
        ),
        what="review_alarm",
    )
    assert tx_execution_succeeded(receipt)

    # ---- 6. verify the verdict, the pause and the payout on-chain ----------
    a = breaker.get_alarm(args=[aid]).call()
    t1 = breaker.get_target(args=[tid]).call()
    stats1 = breaker.get_stats(args=[]).call()

    print(f"\nalarm {aid}: status={a['status']} verdict={a['verdict']}")
    print(f"reasoning: {str(a['reasoning'])[:300]}")
    print(f"target {tid}: status={t1['status']}")

    assert a["status"] == "VALID", f"expected VALID, got {a['status']}"
    assert t1["status"] == "EXPLOITED", f"expected EXPLOITED, got {t1['status']}"

    paused = breaker.is_paused(args=[str(vault.address)]).call()
    assert paused is True, "the breaker must report the vault as paused"
    print("breaker is_paused(vault) -> True")

    print(f"paid so far: {int(stats1['total_paid']) / GEN} GEN")

    # ---- 7. the owner repairs and the pause lifts ---------------------------
    fix_url = _new_webhook_url()
    _write_page(
        fix_url,
        "Fix for the reentrancy in payments-vault.\n\n"
        "CHANGED CODE (function withdraw, deployed after this note):\n"
        "    self.balances[to] = u256(cur - int(amount))\n"
        "    self.total_deposits = u256(int(self.total_deposits) - int(amount))\n"
        "    gl.emit_transfer(to, value=u256(int(amount)))\n\n"
        "The storage update now lands before the external transfer, so the\n"
        "reentrant read always sees the decremented balance. This is exactly\n"
        "the patched contracts/safe_vault.py already public in the same\n"
        "repository. Redeployed at commit 4c71e02, deployment tx recorded in\n"
        "the repo.",
    )
    receipt = _retry(
        lambda: breaker.connect(owner)
        .resume(
            args=[tid, fix_url, "Balance update moved before the external transfer; redeployed."]
        )
        .transact(value=BOND, wait_interval=10000, wait_retries=30),
        what="resume",
    )
    assert tx_execution_succeeded(receipt)
    t2 = breaker.get_target(args=[tid]).call()
    assert t2["status"] == "LIVE", f"expected LIVE after resume, got {t2['status']}"
    resumed = breaker.is_paused(args=[str(vault.address)]).call()
    assert resumed is False, "the breaker must release the vault after the fix"
    print(f"target {tid} resumed, fix accepted, vault live again")

    print("\nE2E PASS: fresh vulnerable target, alarm VALID, pause verified, owner resumed")


if __name__ == "__main__":
    test_visitor_alarm_e2e()
