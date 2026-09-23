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
        A contract owner stakes a bail and registers with the breaker. From
        then on, <em>anyone</em> who can prove a live exploit can pull the
        brakes — no keys, no committee, no office hours.
      </p>

      <h3>The alarm</h3>
      <ol>
        <li>
          A third party stakes a <strong>0.01 GEN bond</strong> and files an
          alarm with a public report page: the vulnerable code, the
          reproduction, the money movement.
        </li>
        <li>
          The report must carry the review's <strong>nonce</strong>, pinned
          on-chain before the review runs. A page written before the alarm
          cannot answer for it.
        </li>
        <li>
          Validators fetch the report themselves and judge it under the
          equivalence principle: both must reach the same verdict before
          anything is written.
        </li>
      </ol>

      <h3>The verdict</h3>
      <p>
        <strong>Exploit confirmed:</strong> the target is paused, and a
        quarter of its bail pays the reporter. False alarms burn the bond
        into the bail — accusing costs something. Unreachable reports record
        a failed attempt and keep the alarm open until the review budget runs
        out.
      </p>

      <h3>The resume</h3>
      <p>
        The owner lifts the pause by staking the alarm bond and pointing at a
        concrete fix page. The validators judge the fix the same way. The bond
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
        Everything above is code you can read, not a description of code. The
        repo holds the breaker, the protected vault, and a pre-patch
        vulnerable vault that the demo alarms quote line for line.
      </p>
      <ul className="link-list">
        <li>
          <a href={REPO_MAIN} target="_blank" rel="noreferrer">
            Full source tree
          </a>
        </li>
        <li>
          <a href={VULNERABLE_VAULT_RAW} target="_blank" rel="noreferrer">
            Vulnerable vault fixture (what a report quotes)
          </a>
        </li>
        <li>
          <a href={E2E_TEST_BLOB} target="_blank" rel="noreferrer">
            The end-to-end alarm flow, as an integration test
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
