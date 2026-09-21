import { Alarm } from "../lib/types";
import { formatClock } from "../config";

export function VerdictPlate({ alarm }: { alarm: Alarm }) {
  if (alarm.status === "PENDING") {
    return (
      <div className="plate pending">
        <div className="plate-head">
          <span className="plate-state">no verdict yet</span>
          <span className="plate-when">
            round {alarm.rounds + 1}
            {alarm.failedAttempts > 0
              ? ` · ${alarm.failedAttempts} failed attempt${alarm.failedAttempts > 1 ? "s" : ""}`
              : ""}
          </span>
        </div>
        <p className="plate-body">
          The reviewers have not read this report yet. Anyone can trigger the
          review once the report page carries the nonce.
        </p>
      </div>
    );
  }

  const tone =
    alarm.status === "VALID" ? "fired" : alarm.status === "REJECTED" ? "rejected" : "expired";
  const headline =
    alarm.status === "VALID"
      ? "exploit confirmed"
      : alarm.status === "REJECTED"
        ? "alarm rejected"
        : "review budget spent";

  return (
    <div className={`plate ${tone}`}>
      <div className="plate-head">
        <span className="plate-state">{headline}</span>
        <span className="plate-when">{formatClock(alarm.settledAt)}</span>
      </div>
      {alarm.verdict && (
        <p className="plate-verdict mono">validators said: {alarm.verdict}</p>
      )}
      {alarm.reasoning && <p className="plate-body">{alarm.reasoning}</p>}
      {alarm.fixHash && <p className="plate-hash mono">fix_hash {alarm.fixHash}</p>}
    </div>
  );
}
