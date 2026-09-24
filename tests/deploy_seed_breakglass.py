"""Deploy BreakGlass + SafeVault on StudioNet and seed a live demo.

Run: gltest --network studionet tests/deploy_seed_breakglass.py -v -s

The seed leaves the board with every state represented:
  - a protected vault that went through alarm -> pause -> fix -> live
    (its alarm VALID, paused again? no: resumed, then closed cleanly)
  - a rejected alarm from a stale report (bond burned into the bail)
  - a fresh live target with no alarm, ready for a visitor to alarm
Print the contract addresses at the end; they go into the frontend config.
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
    "PoC: withdraw_for() drains any account's balance with no authorization "
    "check and pays the caller. The exploit moves funds without authority "
    "and reproduces on the live contract."
)


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


def _archive_page(vault_hex: str) -> str:
    """The deployed source the validators compare report quotes against."""
    return (
        "safe-vault - deployed source - registered contract: " + vault_hex + "\n\n"
        "    @gl.public.write\n"
        "    def withdraw(self, amount: u256) -> None:\n"
        "        to = gl.message.sender_address\n"
        "        cur = int(self.balances.get(to, u256(0)))\n"
        "        if int(amount) <= 0 or int(amount) > cur:\n"
        "            raise gl.vm.UserError(\"withdraw more than your balance\")\n"
        "        gl.emit_transfer(to, value=u256(int(amount)))\n"
        "        self.balances[to] = u256(cur - int(amount))\n\n"
        "    @gl.public.write\n"
        "    def withdraw_for(self, from_hex: str, amount: u256) -> None:\n"
        "        # BUG: no authorization at all. The funds come out of ``from``'s\n"
        "        # balance and land in the CALLER's wallet: anyone can drain anyone.\n"
        "        src = Address(from_hex)\n"
        "        cur = int(self.balances.get(src, u256(0)))\n"
        "        if int(amount) <= 0 or int(amount) > cur:\n"
        "            raise gl.vm.UserError(\"withdraw more than that balance\")\n"
        "        to = gl.message.sender_address\n"
        "        self.balances[src] = u256(cur - int(amount))\n"
        "        gl.emit_transfer(to, value=u256(int(amount)))\n"
    )


def _exploit_page(vault_hex: str, nonce: str) -> str:
    return f"""EXPLOIT REPORT - safe-vault - unauthorized withdrawal path

REGISTERED CONTRACT: {vault_hex}

VULNERABLE FUNCTION (quoted from the registered source archive, function
withdraw_for):

    @gl.public.write
    def withdraw_for(self, from_hex: str, amount: u256) -> None:
        # BUG: no authorization at all. The funds come out of ``from``'s
        # balance and land in the CALLER's wallet: anyone can drain anyone.
        src = Address(from_hex)
        cur = int(self.balances.get(src, u256(0)))
        if int(amount) <= 0 or int(amount) > cur:
            raise gl.vm.UserError("withdraw more than that balance")
        to = gl.message.sender_address
        self.balances[src] = u256(cur - int(amount))
        gl.emit_transfer(to, value=u256(int(amount)))

WHY THIS IS AN UNAUTHORIZED MONEY MOVEMENT: the function takes any wallet
address as ``from_hex`` and moves that wallet's vault balance out to
``gl.message.sender_address`` (the caller). There is no owner check, no
allowance, no signature: any account can empty any other account's balance
in one call. The funds leave the victim without the victim's authority,
which is exactly an unauthorized money movement on the deployed contract.

REPRODUCTION (any caller, no privileges needed):

  1. The victim deposits: deposit() with value 1 GEN. The victim's vault
     balance is now 1 GEN.
  2. The attacker calls withdraw_for(victim_address, 1 GEN). The only check
     compares 1 GEN against the VICTIM's balance, which passes. The victim's
     balance is zeroed and the 1 GEN is transferred to the attacker's wallet.
  3. The attacker never deposited anything.

OBSERVED EFFECT: the victim's deposited funds leave the vault to the
attacker with no authorization from the victim. The attack path is live on
the registered contract at the address above; the vulnerable function is
still deployed.

CONTRACT: {vault_hex}
AUDIT NONCE: {nonce}
"""


def _fix_page(vault_hex: str) -> str:
    return (
        "FIX REPORT - safe-vault - unauthorized withdraw_for removed\n\n"
        "REGISTERED CONTRACT: " + vault_hex + "\n\n"
        "CHANGED CODE (deployed source after this fix):\n\n"
        "    @gl.public.write\n"
        "    def withdraw(self, amount: u256) -> None:\n"
        "        to = gl.message.sender_address\n"
        "        cur = int(self.balances.get(to, u256(0)))\n"
        "        if int(amount) <= 0 or int(amount) > cur:\n"
        "            raise gl.vm.UserError(\"withdraw more than your balance\")\n"
        "        gl.emit_transfer(to, value=u256(int(amount)))\n"
        "        self.balances[to] = u256(cur - int(amount))\n\n"
        "    # withdraw_for() is DELETED. It was the only function that moved\n"
        "    # another account's balance, and it had no authorization check.\n\n"
        "DIFF (unified, against the previously deployed source):\n\n"
        "    -    @gl.public.write\n"
        "    -    def withdraw_for(self, from_hex: str, amount: u256) -> None:\n"
        "    -        src = Address(from_hex)\n"
        "    -        cur = int(self.balances.get(src, u256(0)))\n"
        "    -        if int(amount) <= 0 or int(amount) > cur:\n"
        "    -            raise gl.vm.UserError(\"withdraw more than that balance\")\n"
        "    -        to = gl.message.sender_address\n"
        "    -        self.balances[src] = u256(cur - int(amount))\n"
        "    -        gl.emit_transfer(to, value=u256(int(amount)))\n\n"
        "WHY THE EXPLOIT NO LONGER WORKS: the unauthorized path is gone from\n"
        "the deployed source. withdraw() only moves the caller's own balance,\n"
        "so no call can move another account's funds anymore. The attack path\n"
        "from the accepted alarm is closed on the registered contract above.\n\n"
        "DEPLOYMENT: the patched source was redeployed as this contract's\n"
        "registered code; commit 9f83ab1 in the repository records the\n"
        "change and the deployment transaction."
    )


def _wait_target_status(breaker, tid, want, tries=30, pause=3):
    last = None
    for _ in range(tries):
        last = breaker.get_target(args=[tid]).call()
        if last["status"] == want:
            return last
        time.sleep(pause)
    return last


def test_deploy_and_seed():
    main()


def main():
    accounts = get_accounts()
    owner, reporter, visitor = accounts[0], accounts[1], accounts[2]

    breaker = get_contract_factory("BreakGlass").deploy(account=owner)
    print(f"\nBREAKER={breaker.address}")

    vault_factory = get_contract_factory("SafeVault")

    def _register(vault_hex: str, label: str) -> int:
        archive_url = _new_webhook_url()
        _write_page(archive_url, _archive_page(vault_hex))
        receipt = (
            breaker.connect(owner)
            .register_target(args=[vault_hex, label, archive_url])
            .transact(value=BAIL, wait_interval=10000, wait_retries=15)
        )
        assert tx_execution_succeeded(receipt), f"register {label} failed"
        return int(breaker.get_stats(args=[]).call()["targets"])

    # ---- target 1: a funded vault that will go through the full arc ------
    vault1 = vault_factory.deploy(args=[str(breaker.address)], account=owner)
    receipt = (
        vault1.connect(owner)
        .deposit(args=[])
        .transact(value=GEN, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    vault1_hex = str(vault1.address)
    tid1 = _register(vault1_hex, "safe-vault")
    print(f"VAULT1={vault1_hex} target={tid1}")

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
    _write_page(url1, _exploit_page(vault1_hex, nonce1))

    receipt = breaker.review_alarm(args=[aid1]).transact(
        wait_interval=10000, wait_retries=25
    )
    assert tx_execution_succeeded(receipt)
    print(f"TX review_alarm (alarm -> EXPLOITED): {receipt['hash']}")
    t1 = _wait_target_status(breaker, tid1, "EXPLOITED")
    assert t1["status"] == "EXPLOITED", f"target 1 should be paused, got {t1['status']}"
    print(f"alarm {aid1} -> EXPLOITED, vault paused")

    # ---- target 2: a second vault, alarmed with a stale report ----------
    vault2 = _retry(
        lambda: vault_factory.deploy(args=[str(breaker.address)], account=owner),
        what="deploy vault2",
    )
    vault2_hex = str(vault2.address)
    tid2 = _register(vault2_hex, "cold-storage")

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
        "Old writeup: hypothetical withdrawal bug in a similar vault. "
        "No reproduction, no trace, no nonce.",
    )
    receipt = breaker.review_alarm(args=[aid2]).transact(
        wait_interval=10000, wait_retries=25
    )
    assert tx_execution_succeeded(receipt)
    print(f"TX review_alarm (stale -> REJECTED, bond burned): {receipt['hash']}")
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
    vault3_hex = str(vault3.address)
    tid3 = _register(vault3_hex, "treasury")
    print(f"VAULT3={vault3_hex} target={tid3} (live, no alarm)")

    # ---- owner resumes vault 1 with a fix --------------------------------
    fix_url = _new_webhook_url()
    _write_page(fix_url, _fix_page(vault1_hex))
    receipt = (
        breaker.connect(owner)
        .resume(
            args=[
                tid1,
                fix_url,
                "Removed the unauthorized withdraw_for path; redeployed.",
            ]
        )
        .transact(value=BOND, wait_interval=10000, wait_retries=25)
    )
    assert tx_execution_succeeded(receipt)
    print(f"TX resume (fix accepted, vault unpaused): {receipt['hash']}")
    t1 = _wait_target_status(breaker, tid1, "LIVE")
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
