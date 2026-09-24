import { Link } from "react-router-dom";
import {
  REPO_MAIN,
  VULNERABLE_VAULT_RAW,
  E2E_TEST_BLOB,
} from "../lib/links";

export function HowItWorks() {
  return (
    <div className="prose">
      <h2>How BreakGlass works</h2>
      <p className="lead">
        Four moves, all of them on-chain: register, alarm, verdict, resume.
        Nothing here needs a phone call.
      </p>

      <h3>The problem</h3>
      <p>
        When a contract is exploited, the people who could stop the damage are
        the ones asleep, away, or compromised. Waiting for a multisig is
        waiting for the drain to finish.
      </p>

      <h3>The machine</h3>
      <p>
        A contract owner stakes a bail and registers with the breaker, and
        the registration is a two-sided handshake: the contract must pin this
        breaker at deploy time, answer the breaker's consent read, and
        confirm the registration with its own write. Nobody can register a
        contract that never heard of the breaker, nobody can register it
        twice, and closing frees the address for a fresh registration. From
        then on, <em>anyone</em> who can prove a live exploit can pull the
        brakes — no keys, no committee, no office hours.
      </p>

      <h3>The alarm</h3>
      <ol>
        <li>
          A third party stakes a <strong>0.01 GEN bond</strong> and files an
          alarm with a public report page: the vulnerable code, the
          reproduction, the money movement, and the registered contract's
          address.
        </li>
        <li>
          The report must carry the review's <strong>nonce</strong>, pinned
          in the contract's storage before the review runs, and must bind to
          the registered contract address. Both echoes are checked in code,
          not by the model. A pre-written report cannot carry the nonce, and
          a report about another contract proves nothing here.
        </li>
        <li>
          Validators fetch the report themselves and judge it against the
          registered source archive; they must agree on the verdict before
          anything is written on-chain.
        </li>
      </ol>

      <h3>The verdict</h3>
      <p>
        <strong>Exploit confirmed:</strong> the target is paused, a quarter
        of its bail pays the reporter, and the reporter's bond comes home.
        False alarms burn the bond into the target's bail — accusing costs
        something, and the owner closes with the pool grown. An alarm naming
        an exploit hash the target already fixed is stale evidence and is
        rejected the same way. Unreachable reports record a failed attempt
        and keep the alarm open until the review budget runs out, at which
        point the bond goes home.
      </p>

      <h3>The resume</h3>
      <p>
        The owner lifts the pause by staking the alarm bond and pointing at a
        concrete fix page that names the registered contract. The validators
        judge the fix the same way, against the registered archive. The stake
        comes back when the fix holds; the target stays paused until it does.
      </p>

      <h3>The gate</h3>
      <p>
        Protected contracts read the breaker's verdict for themselves before
        moving money. No keeper, no cron: when the breaker pauses a target,
        the target stops moving funds on its very next call, and starts again
        the moment the breaker resumes it.
      </p>

      <h3>The numbers</h3>
      <table className="num-table">
        <tbody>
          <tr>
            <th>Minimum bail</th>
            <td className="mono">0.1 GEN</td>
          </tr>
          <tr>
            <th>Alarm bond</th>
            <td className="mono">0.01 GEN</td>
          </tr>
          <tr>
            <th>Reporter reward</th>
            <td className="mono">25% of the bail</td>
          </tr>
        </tbody>
      </table>

      <h3>See the machine for yourself</h3>
      <p>
        Nothing above is a metaphor. The repo holds the breaker, the vault it
        protects, and an intentionally vulnerable vault that alarm reports
        quote line for line.
      </p>
      <ul className="link-list">
        <li>
          <a href={REPO_MAIN} target="_blank" rel="noreferrer">
            Read the full source tree
          </a>
        </li>
        <li>
          <a href={VULNERABLE_VAULT_RAW} target="_blank" rel="noreferrer">
            The vulnerable vault, exactly as a report quotes it
          </a>
        </li>
        <li>
          <a href={E2E_TEST_BLOB} target="_blank" rel="noreferrer">
            The alarm flow end to end, as a runnable test
          </a>
        </li>
      </ul>

      <p>
        <Link className="btn primary" to="/register">
          Put a contract under it
        </Link>
      </p>
    </div>
  );
}
