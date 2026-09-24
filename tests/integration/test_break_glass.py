"""Integration tests for BreakGlass on StudioNet.

Run: gltest --network studionet tests/integration/test_break_glass.py -v -s

These exercise the real consensus path and the real cross-contract
handshake: the breaker reads the vault's consent view, the vault confirms
the registration with its own write, validators fetch a live public report
page and must agree on the verdict through the comparative equivalence
principle, and the accepted verdict pauses the second contract. The report
endpoints are rewritten per run through a public host, because the report
must carry the review nonce that only exists after the alarm is filed. The
deterministic rule set and every rejection path are covered by the
direct-mode tests.
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
    "PoC: withdraw_for() drains any account's balance with no authorization "
    "check and pays the caller. The exploit moves funds without authority "
    "and reproduces on the live contract."
)
FIX_NOTE = "Removed the unauthorized withdraw_for path and redeployed the contract."

# A concrete, self-contained exploit report: the vulnerable function quoted
# from the registered archive, why it is unauthorized, and the reproduction.
# The validators read the page as text, compare the quotes against the
# registered archive, and must judge it as a real, live exploit.
EXPLOIT_PAGE = """EXPLOIT REPORT - safe-vault - unauthorized withdrawal path

REGISTERED CONTRACT: {contract}

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


def _archive_page() -> str:
    """The deployed source the validators compare quoted code against.

    This is the same vulnerable withdraw_for() the exploit report quotes;
    the validators fetch it from the registered archive URL and check the
    report's quotes against it.
    """
    return (
        "safe-vault - deployed source:\n\n"
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


def _register(breaker, account, vault_addr_hex, vault=None):
    """Register through the consent handshake and return the target id.

    The breaker reads the vault's breakglass_registration view cross-contract
    inside this transaction: the vault must pin this breaker and report the
    registrant as its own owner, or the registration reverts. The archive URL
    serves the real deployed source, so the validators can check report
    quotes against it.
    """
    archive_url = _new_webhook_url()
    _write_page(archive_url, _archive_page())
    receipt = (
        breaker.connect(account)
        .register_target(
            args=[vault_addr_hex, "safe-vault", archive_url]
        )
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


def _wait_target_status(breaker, tid, want, tries=30, pause=3):
    """Poll the target status until it lands (write propagation can lag a
    receipt by a few seconds on the live network)."""
    last = None
    for _ in range(tries):
        last = breaker.get_target(args=[tid]).call()
        if last["status"] == want:
            return last
        time.sleep(pause)
    return last


def _wait_alarm_status(breaker, aid, want, tries=30, pause=3):
    last = None
    for _ in range(tries):
        last = breaker.get_alarm(args=[aid]).call()
        if last["status"] == want:
            return last
        time.sleep(pause)
    return last


def _publish_report(breaker, url, aid, account, vault_addr_hex):
    """Reserve the review nonce on-chain, then write the report for it.

    The report carries the nonce and the registered contract address; the
    review's code-level echo checks demand both.
    """
    receipt = (
        breaker.connect(account)
        .reserve_review_nonce(args=[aid])
        .transact(wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    nonce = str(breaker.alarm_review_nonce(args=[aid]).call())
    _write_page(
        url,
        EXPLOIT_PAGE + f"\nCONTRACT: {vault_addr_hex}\nAUDIT NONCE: {nonce}\n",
    )
    return nonce


@pytest.mark.integration
def test_registration_consent_on_real_vault():
    """The handshake: a foreign registrant and an unpinned breaker refuse.

    The vault here is a real second contract pinned to this breaker, so the
    consent view and the confirmation write run cross-contract on the live
    network.
    """
    accounts = get_accounts()
    owner, stranger = accounts[0], accounts[1]

    breaker = _deploy(owner)
    vault_factory = get_contract_factory("SafeVault")
    vault = vault_factory.deploy(args=[str(breaker.address)], account=owner)
    vault_hex = str(vault.address)

    # A stranger stakes a bail for a contract he does not own: refused.
    receipt = (
        breaker.connect(stranger)
        .register_target(
            args=[vault_hex, "stolen", "https://webhook.site/not-an-archive"]
        )
        .transact(value=BAIL, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_failed(receipt), "a stranger registered someone else's contract"
    assert int(breaker.get_stats(args=[]).call()["targets"]) == 0

    # A duplicate registration after a successful one: refused.
    receipt = (
        breaker.connect(owner)
        .register_target(
            args=[vault_hex, "safe-vault", _new_webhook_url()]
        )
        .transact(value=BAIL, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    tid = int(breaker.get_stats(args=[]).call()["targets"])
    receipt = (
        breaker.connect(owner)
        .register_target(
            args=[vault_hex, "safe-vault again", _new_webhook_url()]
        )
        .transact(value=BAIL, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_failed(receipt), "the same contract registered twice"
    assert int(breaker.get_stats(args=[]).call()["targets"]) == 1

    # The consent read is the binding handshake: the vault's own code
    # reports this breaker and the owner, which is what let the registration
    # land. The registry is the single source of truth.
    info = vault.breakglass_registration(args=[]).call()
    assert str(info.get("breaker", "")) != ""
    assert int(breaker.get_stats(args=[]).call()["live"]) == 1

    # The owner closes, and the address is freed for a fresh registration.
    receipt = (
        breaker.connect(owner)
        .close_target(args=[tid])
        .transact(wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    t = breaker.get_target(args=[tid]).call()
    assert t["status"] == "CLOSED"

    # A closed registration frees the address: the same contract can
    # register again under the breaker.
    receipt = (
        breaker.connect(owner)
        .register_target(
            args=[vault_hex, "safe-vault renewed", "https://github.com/example/safe-vault"]
        )
        .transact(value=BAIL, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)


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
    vault_hex = str(vault.address)

    # Owner funds the vault. Money moves while no alarm stands.
    receipt = (
        vault.connect(owner)
        .deposit(args=[])
        .transact(value=GEN, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)

    tid = _register(breaker, owner, vault_hex)

    # A third party stakes the bond and files the alarm.
    aid, url = _file_alarm(breaker, reporter, tid)

    # Publish the exploit report written for this review's nonce.
    _publish_report(breaker, url, aid, reporter, vault_hex)

    receipt = (
        breaker.review_alarm(args=[aid])
        .transact(wait_interval=10000, wait_retries=25)
    )
    assert tx_execution_succeeded(receipt)

    t = _wait_target_status(breaker, tid, "EXPLOITED")
    a = _wait_alarm_status(breaker, aid, "VALID")
    print(f"\n[diag] alarm status={a['status']} verdict={a['verdict']}")
    print(f"[diag] reasoning={str(a['reasoning'])[:400]}")
    assert t["status"] == "EXPLOITED", f"expected the vault paused, got {t['status']}"

    # The pause check reads True for the vault's address.
    assert breaker.is_paused(args=[vault_hex]).call() is True

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

    # The reporter collects a quarter of the bail, and the reporter's own
    # bond comes home on top of the reward.
    stats = breaker.get_stats(args=[]).call()
    assert int(stats["total_paid"]) == REWARD
    assert int(stats["total_bonds"]) == 0, "the reporter's bond must be back"

    # The owner publishes a fix and stakes the resume bond. The page must
    # convince live validators: the removed function, the reason the attack
    # path is gone, and the registered contract address.
    fix_url = _new_webhook_url()
    _write_page(
        fix_url,
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
        "change and the deployment transaction.",
    )
    receipt = (
        breaker.connect(owner)
        .resume(args=[tid, fix_url, FIX_NOTE])
        .transact(value=BOND, wait_interval=10000, wait_retries=25)
    )
    assert tx_execution_succeeded(receipt)

    t = _wait_target_status(breaker, tid, "LIVE")
    assert t["status"] == "LIVE", f"expected the vault resumed, got {t['status']}"

    # The resume stake is back with the owner.
    stats = breaker.get_stats(args=[]).call()
    assert int(stats["total_bonds"]) == 0

    # Money moves again.
    receipt = (
        vault.connect(owner)
        .deposit(args=[])
        .transact(value=GEN, wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)

    # Close returns the remaining bail and unregisters the vault.
    receipt = (
        breaker.connect(owner)
        .close_target(args=[tid])
        .transact(wait_interval=10000, wait_retries=15)
    )
    assert tx_execution_succeeded(receipt)
    stats = breaker.get_stats(args=[]).call()
    assert int(stats["total_bail"]) == 0, "the close must drain the bail"
    assert int(stats["bail_consistent"]) == 1
    assert int(stats["bonds_consistent"]) == 1


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
    # The consent handshake demands a real, consenting contract, so the
    # alarm flies against a deployed vault instead of a bare address.
    vault = get_contract_factory("SafeVault").deploy(
        args=[str(breaker.address)], account=owner
    )
    tid = _register(breaker, owner, str(vault.address))
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
    assert int(stats["total_burned"]) == BOND
    # The burned bond grew the target's bail: the owner closes with more
    # than he staked.
    assert int(stats["total_bail"]) == BAIL + BOND


@pytest.mark.integration
def test_unreachable_report_fails_and_gates_retries():
    """A dead report URL burns a review attempt, keeps the alarm open, and
    the one-hour cooldown gates the next run on the live clock."""
    accounts = get_accounts()
    owner, reporter = accounts[0], accounts[1]

    breaker = _deploy(owner)
    vault = get_contract_factory("SafeVault").deploy(
        args=[str(breaker.address)], account=owner
    )
    tid = _register(breaker, owner, str(vault.address))

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
