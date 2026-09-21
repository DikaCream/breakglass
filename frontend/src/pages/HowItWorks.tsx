import { Link } from "react-router-dom";

export function HowItWorks() {
  return (
    <div className="prose">
      <h2>How BreakGlass works</h2>

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
          The report must carry the review's <strong>nonce</strong>. The nonce
          is pinned on-chain before the review and derived from facts the
          alarm already fixed, so a page written before the alarm cannot
          answer for it.
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

      <p>
        <Link className="btn primary" to="/register">
          Put a contract under it
        </Link>
      </p>
    </div>
  );
}
