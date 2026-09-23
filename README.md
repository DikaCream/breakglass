# BreakGlass

A contract can be exploited at 3am on a Sunday. Its owner might be asleep, traveling, or the multisig might be short one signature. BreakGlass is the emergency brake that doesn't wait for any of that: anyone who can prove a live exploit against a protected contract pauses it on-chain, and validators decide from the report, not from whoever holds the keys.

It runs on [GenLayer](https://genlayer.com), so the verdict itself is consensus output. Validators fetch the report themselves and both must land on the same verdict before anything is written. No oracle committee, no office hours.

## How the pieces fit

1. **Register.** The owner stakes 0.1 GEN bail and points the breaker at their contract plus a source archive. From then on, a confirmed alarm pauses the contract and a quarter of the bail pays whoever proved the exploit.
2. **Alarm.** A third party stakes a 0.01 GEN bond and files a report URL. The report has to show the vulnerable code, a working reproduction, and the money movement. Hypotheticals don't count.
3. **Nonce handshake.** Before the review runs, the reporter pins a nonce on-chain and writes it into the report page. The nonce is derived from the alarm's own history, so a page written before the alarm existed can't answer for it. The contract checks the echo in code, not by trusting the model.
4. **Review.** Validators fetch the report and judge it; they must agree on the verdict before anything is written on-chain. Exploited: the target pauses and the reporter collects. Rejected: the bond burns into the bail. Unreachable: the attempt records and the alarm stays open until the review budget runs out.
5. **Resume.** The owner stakes the bond again and points at a fix page (a diff, a patch, a redeployment record). Validators judge the fix the same way. Bond back when it holds.
6. **The gate.** The protected contract reads the breaker's verdict before moving money. No keeper, no cron. Paused means the very next deposit or withdrawal refuses; resumed means money moves again.

The demo target in `contracts/safe_vault.py` is a small deposit vault wired to the breaker this way, so the pause surface is real, not a diagram.

## Try it

- App: https://breakglass-flax.vercel.app
- Contract on StudioNet: `0x91Bc965E0939F47Cc9aAFCD42ca11a683578484f`

Walk the whole flow in the browser:

1. Open a target with no open alarm and press **File an alarm**.
2. Need code to quote? The repo ships `contracts/_vulnerable_vault.py`, a pre-patch target you can deploy as your own and report on honestly.
3. Point the report at a page you control (a fresh webhook.site page works) and describe the exploit.
4. Press **Reserve nonce**, then copy the nonce into the report page before going further.
5. Press **Run the review**. Validators fetch the page and the verdict lands on-chain.
6. Own a paused target? Submit a fix page under **Resume with a fix** to lift the pause.

Every action button ends in a contract call.

## Repo layout

```
contracts/break_glass.py     the breaker: targets, alarms, nonce handshake, verdicts, resume
contracts/safe_vault.py      demo target that consults the breaker before moving money
contracts/_vulnerable_vault.py   pre-patch target a report can quote honestly
tests/direct/                the deterministic rule set, exhaustively, on a local VM
tests/e2e_visitor_alarm.py    full visitor arc on live StudioNet: alarm, nonce, pause, payout, resume
tests/integration/           the consensus paths on StudioNet
tests/deploy_seed_breakglass.py   deploys and seeds a board with every state on it
frontend/                    Vite + React app
```

## Tests

Direct mode runs the whole rule set against a local VM: alarm guards, bond accounting, nonce reservation and consumption, cooldown and review budget, the vault's local gate side. 31 tests pass there, and each guard was mutation-checked (the guard was disabled, the matching test failed, the guard was restored).

StudioNet runs the parts direct mode can't: two real contracts on the real network, the validators fetching a live report page and agreeing on the verdict, the vault refusing a deposit while paused, the fix accepted and the money moving again.

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
