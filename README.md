# BreakGlass

A contract can be exploited at 3am on a Sunday. Its owner might be asleep, traveling, or the multisig might be short one signature. BreakGlass is the emergency brake that doesn't wait for any of that: anyone who can prove a live exploit against a protected contract pauses it on-chain, and validators decide from the report, not from whoever holds the keys.

It runs on [GenLayer](https://genlayer.com), so the verdict itself is consensus output. Validators fetch the report themselves and both must land on the same verdict before anything is written. No oracle committee, no office hours.

## How the pieces fit

1. **Register, with consent.** The contract's own owner stakes 0.1 GEN bail and points the breaker at the contract plus a source archive of the deployed code. Registration is a two-sided handshake: the breaker reads the contract's `breakglass_registration` view and requires that the contract pinned THIS breaker at deploy time and reports the registrant as its own owner. A contract that never heard of the breaker cannot be registered by anyone, a contract already under the breaker is refused twice, and closing frees the address for a fresh registration.
2. **Alarm.** A third party stakes a 0.01 GEN bond and files a report URL. The report has to show the vulnerable code quoted from the registered archive, a working reproduction, the money movement, and the registered contract's address. Hypotheticals and other contracts' bugs don't count.
3. **Nonce handshake.** Before the review runs, the reporter pins a nonce on-chain and writes it into the report page. The UI reserves it first and shows it only after the reservation transaction landed. The nonce is derived from the alarm's own history, so a page written before the alarm existed can't answer for it.
4. **Review, bound to the registered contract.** Validators fetch the report and judge it against the registered source archive; they must agree on the verdict before anything is written. The breaker checks the report's nonce echo and contract-address echo in code, not by trusting the model: a stale page or a report about another contract is downgraded to UNPROVEN even if the judge is convinced. An alarm naming an exploit hash the target already fixed is rejected as stale evidence; a new exploit needs new evidence. Exploited: the target pauses, a quarter of the bail pays the reporter, and the reporter's bond comes home. Rejected: the bond burns into the target's bail, so the owner closes with the pool grown. Unreachable: the attempt records and the alarm stays open until the review budget runs out, then the bond goes home.
5. **Resume.** The owner stakes the bond and points at a fix page (the changed code, a diff, a redeployment record) that names the registered contract. Validators judge the fix the same way, against the archive. The stake comes back when the fix holds.
6. **Close.** The owner ends the protection and takes the remaining bail home, including any bonds false reporters burned into it.
7. **The gate.** The protected contract reads the breaker's verdict before moving money. No keeper, no cron. Paused means the very next deposit or withdrawal refuses; resumed means money moves again.

The demo target in `contracts/safe_vault.py` is a small deposit vault wired to the breaker this way, so the pause surface is real, not a diagram.

## Try it

- App: https://breakglass-flax.vercel.app
- Contract on StudioNet: `0x9b25fb5CaBc2a368A179832096275F5022B59225`

The seeded board carries the states side by side: target 1 went through a confirmed alarm, a pause, an accepted fix, and is live again; target 2 carries a rejected stale alarm whose bond burned into its bail; target 3 is live and untouched, waiting for a visitor.

Proof transactions from the seed run:

- `0xda942f7d73b6d567fa9be383ae88d5c7e6b4b46313f657f7f810a71e7061eadb`, the review that confirmed the exploit: validators verified the nonce, the registered contract address, and a byte-for-byte archive quote, then paused the vault.
- `0x3d862ead42f9d094c3087c1a1ead62ca162fd1b7a9bd9519b1f16e8e04b27651`, the stale report rejected: no nonce, bond burned into the bail.
- `0x040be704affe0388e6f724d7757b65bcb47f10aa5a374da82b271e6a5de6e18f`, the fix accepted and the vault unpaused.

Walk the whole flow in the browser:

1. Open a target with no open alarm and press **File an alarm**.
2. Need code to quote? The repo ships `contracts/_vulnerable_vault.py`, a pre-patch target you can deploy as your own and report on honestly.
3. Point the report at a page you control (a fresh webhook.site page works) and describe the exploit.
4. Press **Reserve the review nonce**, then copy the nonce and the contract address into the report page before anyone runs the review.
5. Press **Run the review**. Validators fetch the page and the verdict lands on-chain.
6. Own a paused target? Submit a fix page under **Resume with a fix** to lift the pause.

Every action button ends in a contract call.

## Repo layout

```
contracts/break_glass.py     the breaker: consent, targets, alarms, nonce handshake, verdicts, resume, close
contracts/safe_vault.py      demo target that pins the breaker and consults it before moving money
contracts/_vulnerable_vault.py   pre-patch target a report can quote honestly
tests/direct/                the deterministic rule set, exhaustively, on a local VM
tests/integration/           the consent handshake and consensus paths on StudioNet
tests/deploy_seed_breakglass.py   deploys and seeds a board with every state on it
frontend/                    Vite + React app
```

## Accounting

Every GEN that enters the breaker is tracked. Registrations and burned bonds credit the bail escrow; reporter rewards and close refunds debit it; alarm bonds and resume stakes credit the bond escrow and leave only back to a wallet. `get_stats` exposes the lifetime flows (`total_bail_in/out`, `total_bonds_in/out`, `total_burned`, `total_paid`) alongside reconciliation flags (`bail_consistent`, `bonds_consistent`) that the direct tests assert on every outcome path.

## Tests

Direct mode runs the whole rule set against a local VM: the consent handshake (foreign registrant, unpinned breaker, duplicate registration, self-registration, renewal after close), alarm guards, per-outcome fund conservation, the full exploit -> resume -> close arc, the rejected-alarm -> close arc, the expired-alarm -> close arc, contract-bound review echoes, stale-exploit dedup, nonce reservation and consumption, cooldown and review budget, and the vault's local surface. 46 tests pass there, and each guard was mutation-checked (the guard was disabled, the matching test failed, the guard was restored).

StudioNet runs the parts direct mode can't: two real contracts on the real network, the cross-contract consent read inside the registration transaction, a stranger's registration reverting, a duplicate refusing, the validators fetching a live report page and agreeing on the verdict, the vault refusing a deposit while paused, the fix accepted and the money moving again, and the close draining the bail.

```bash
pip install -e ".[dev]"        # or install gltest per GenLayer docs
python -m pytest tests/direct -q
gltest --network studionet tests/integration/test_break_glass.py -v
```

## Frontend

```bash
cd frontend
npm install
npm run dev
```

Point `VITE_CONTRACT_ADDRESS` at a breaker deployment if you want to run against your own.
