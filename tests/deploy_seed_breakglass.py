"""Deploy BreakGlass + SafeVault on StudioNet and seed a live demo.

Run: gltest --network studionet tests/deploy_seed_breakglass.py -v -s

The seed leaves the board with every state represented:
  - a protected vault that went through pause -> fix -> live (its alarm VALID)
  - a rejected alarm from a stale report (bond burned into the bail)
  - a fresh live target with no alarm, ready for a visitor to alarm
Print the contract addresses at the end; they go into the frontend config.
Run: gltest --network studionet tests/deploy_seed_breakglass.py -v -s
"""

import json
import time
import urllib.request

from gltest import get_accounts, get_contract_factory
from gltest.assertions import tx_execution_succeeded


def _retry(fn, tries=4, pause=8, what="call"):
    """StudioNet occasionally resets a connection mid-flight."""
    last = None
    for i in range(tries):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - any transient error retries
            last = e
            print(f"  [retry] {what} attempt {i + 1} failed: {str(e)[:120]}")
            time.sleep(pause)
    raise last


GEN = 10**18
BAIL = GEN // 10
BOND = GEN // 100

REPORT = (
    "Withdrawal bypass through reentrancy: funds leave the vault without "
    "authority. The vulnerable code, the reproduction and the trace are in "
    "the report."
)

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


def test_deploy_and_seed():
    main()


def main():
    accounts = get_accounts()
    owner, reporter, visitor = accounts[0], accounts[1], accounts[2]

    breaker = get_contract_factory("BreakGlass").deploy(account=owner)
    print(f"\nBREAKER={breaker.address}")

    vault_factory = get_contract_factory("SafeVault")

    # ---- target 1: a funded vault that will go through the full arc ------
    vault1 = vault_factory.deploy(args=[str(breaker.address)], account=owner)
    receipt = (
        vault1.connect(owner)
        .deposit(args=[])
        .transact(value=GEN, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    receipt = (
        breaker.connect(owner)
        .register_target(
            args=[str(vault1.address), "safe-vault", "https://github.com/example/safe-vault"]
        )
        .transact(value=BAIL, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    tid1 = int(breaker.get_stats(args=[]).call()["targets"])
    print(f"VAULT1={vault1.address} target={tid1}")

    # Alarm it, publish the report for the nonce, review -> EXPLOITED.
    url1 = _new_webhook_url()
    receipt = (
        breaker.connect(reporter)
        .file_alarm(args=[tid1, url1, REPORT])
        .transact(value=BOND, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    aid1 = int(breaker.get_stats(args=[]).call()["alarms"])

    receipt = (
        breaker.connect(reporter)
        .reserve_review_nonce(args=[aid1])
        .transact(wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    nonce1 = str(breaker.alarm_review_nonce(args=[aid1]).call())
    _write_page(url1, EXPLOIT_PAGE + f"\nAUDIT NONCE: {nonce1}\n")

    receipt = breaker.review_alarm(args=[aid1]).transact(
        wait_interval=10000, wait_retries=25
    )
    assert tx_execution_succeeded(receipt)
    t1 = breaker.get_target(args=[tid1]).call()
    assert t1["status"] == "EXPLOITED", f"target 1 should be paused, got {t1['status']}"
    print(f"alarm {aid1} -> EXPLOITED, vault paused")

    # ---- target 2: a second vault, alarmed with a stale report ----------
    vault2 = _retry(
        lambda: vault_factory.deploy(args=[str(breaker.address)], account=owner),
        what="deploy vault2",
    )
    receipt = (
        breaker.connect(owner)
        .register_target(
            args=[str(vault2.address), "cold-storage", "https://github.com/example/cold-storage"]
        )
        .transact(value=BAIL, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    tid2 = int(breaker.get_stats(args=[]).call()["targets"])

    url2 = _new_webhook_url()
    receipt = (
        breaker.connect(visitor)
        .file_alarm(args=[tid2, url2, REPORT])
        .transact(value=BOND, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    aid2 = int(breaker.get_stats(args=[]).call()["alarms"])

    # A page written before the alarm: no nonce inside.
    _write_page(
        url2,
        "Old writeup: hypothetical reentrancy in a similar vault. "
        "No reproduction, no trace, no nonce.",
    )
    receipt = breaker.review_alarm(args=[aid2]).transact(
        wait_interval=10000, wait_retries=25
    )
    assert tx_execution_succeeded(receipt)
    a2 = breaker.get_alarm(args=[aid2]).call()
    assert a2["status"] == "REJECTED", f"stale report must reject, got {a2['status']}"
    print(f"alarm {aid2} -> REJECTED (stale page, bond burned)")

    # ---- target 3: a plain live vault, untouched -------------------------
    vault3 = vault_factory.deploy(args=[str(breaker.address)], account=owner)
    receipt = (
        vault3.connect(owner)
        .deposit(args=[])
        .transact(value=GEN, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    receipt = (
        breaker.connect(owner)
        .register_target(
            args=[str(vault3.address), "treasury", "https://github.com/example/treasury"]
        )
        .transact(value=BAIL, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    tid3 = int(breaker.get_stats(args=[]).call()["targets"])
    print(f"VAULT3={vault3.address} target={tid3} (live, no alarm)")

    # ---- owner resumes vault 1 with a fix --------------------------------
    fix_url = _new_webhook_url()
    _write_page(
        fix_url,
        "Fix for the reentrancy in safe-vault.\n\n"
        "CHANGED CODE (function withdraw, deployed after this note):\n"
        "    self.balances[to] = u256(cur - int(amount))\n"
        "    gl.emit_transfer(to, value=u256(int(amount)))\n\n"
        "The storage update now lands before the external transfer, so the\n"
        "reentrant read always sees the decremented balance. Redeployed at\n"
        "commit 9f83ab1, deployment tx recorded in the repo.",
    )
    receipt = (
        breaker.connect(owner)
        .resume(
            args=[
                tid1,
                fix_url,
                "Balance update moved before the external transfer; redeployed.",
            ]
        )
        .transact(value=BOND, wait_interval=10000, wait_retries=25)
    )
    assert tx_execution_succeeded(receipt)
    t1 = breaker.get_target(args=[tid1]).call()
    assert t1["status"] == "LIVE", f"target 1 should be resumed, got {t1['status']}"
    print(f"target {tid1} -> resumed, fix accepted")

    stats = breaker.get_stats(args=[]).call()
    print(
        f"\nFINAL stats: targets={stats['targets']} alarms={stats['alarms']} "
        f"live={stats['live']} paused={stats['paused']} "
        f"bail={stats['total_bail']} bonds={stats['total_bonds']} paid={stats['total_paid']}"
    )
    print(f"\nBREAKER_ADDRESS={breaker.address}")
    print("SEED DONE")


if __name__ == "__main__":
    main()
