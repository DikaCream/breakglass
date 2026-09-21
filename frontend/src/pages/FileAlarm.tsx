import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useBreakGlass } from "../context/BreakGlassContext";
import { ALARM_BOND, formatGen } from "../config";

export function FileAlarm() {
  const { id } = useParams();
  const { run, busy, wallet } = useBreakGlass();
  const navigate = useNavigate();
  const tid = Number(id);

  const [url, setUrl] = useState("");
  const [reason, setReason] = useState("");
  const [localErr, setLocalErr] = useState<string | null>(null);

  const submit = async () => {
    setLocalErr(null);
    if (await run(`alarm-${tid}`, (c) => c.fileAlarm(tid, url.trim(), reason.trim(), ALARM_BOND))) {
      navigate(`/targets/${tid}`);
    }
  };

  return (
    <div className="form-page">
      <h2>File an alarm on target #{tid}</h2>
      <p className="note">
        Stake {formatGen(ALARM_BOND)} GEN and claim this contract is exploited
        right now. The report page must show a concrete, live exploit: the
        vulnerable code, the reproduction, and the money movement. If the
        reviewers confirm it, the target pauses and a quarter of its bail is
        yours. If they reject it, your bond burns into the bail.
      </p>
      {!wallet.address && (
        <p className="note bad">Connect a wallet first. The bond leaves it.</p>
      )}
      <label className="field">
        <span>Report page URL</span>
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://…/the-exploit-report"
        />
      </label>
      <label className="field">
        <span>Why this contract is exploited</span>
        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          rows={4}
          maxLength={2000}
          placeholder="Withdrawal bypass through reentrancy: funds leave without authority, trace inside the report"
        />
      </label>
      {localErr && <p className="note bad">{localErr}</p>}
      <button
        className="btn fire"
        onClick={submit}
        disabled={busy !== null || !url || !reason || !wallet.address}
      >
        {busy === `alarm-${tid}` ? "Staking the bond…" : `Stake ${formatGen(ALARM_BOND)} GEN and file it`}
      </button>
    </div>
  );
}
