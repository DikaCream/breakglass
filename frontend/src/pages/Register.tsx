import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useBreakGlass } from "../context/BreakGlassContext";
import { MIN_BAIL, formatGen } from "../config";

export function Register() {
  const { run, busy, wallet } = useBreakGlass();
  const navigate = useNavigate();

  const [addr, setAddr] = useState("");
  const [label, setLabel] = useState("");
  const [archiveUrl, setArchiveUrl] = useState("");
  const [localErr, setLocalErr] = useState<string | null>(null);

  const submit = async () => {
    setLocalErr(null);
    if (!/^0x[0-9a-fA-F]{40}$/.test(addr.trim())) {
      setLocalErr("The contract address must be a 0x-prefixed 20-byte hex address.");
      return;
    }
    if (await run("register", (c) =>
      c.registerTarget(addr.trim(), label.trim(), archiveUrl.trim(), MIN_BAIL),
    )) {
      navigate("/");
    }
  };

  return (
    <div className="form-page">
      <h2>Put a contract under the breaker</h2>
      <p className="note">
        Registration is a two-sided handshake. Your contract must be built
        for this: it pins this breaker's address at deploy time, answers the
        breaker's consent read from a <span className="mono">breakglass_registration</span> view, and confirms the registration
        with its own write. Only the contract's own owner can register it, a
        contract already under the breaker is refused, and the gate arms only
        after the handshake lands. See the demo vault in the repo for the
        exact surface.
      </p>
      <p className="note">
        Stake {formatGen(MIN_BAIL)} GEN as bail and give a URL where the
        deployed source lives: validators fetch it to judge whether reports
        quote the real code. From then on, a confirmed exploit pauses your
        contract and a quarter of the bail pays the reporter.
      </p>
      {!wallet.address && (
        <p className="note bad">Connect a wallet first. The bail leaves it.</p>
      )}
      <label className="field">
        <span>Protected contract address (built against this breaker)</span>
        <input
          value={addr}
          onChange={(e) => setAddr(e.target.value)}
          placeholder="0x…"
        />
      </label>
      <label className="field">
        <span>Label</span>
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="safe-vault"
          maxLength={120}
        />
      </label>
      <label className="field">
        <span>Source archive URL</span>
        <input
          value={archiveUrl}
          onChange={(e) => setArchiveUrl(e.target.value)}
          placeholder="https://github.com/you/the-contract"
        />
      </label>
      {localErr && <p className="note bad">{localErr}</p>}
      <button
        className="btn primary"
        onClick={submit}
        disabled={busy !== null || !addr || !label || !archiveUrl || !wallet.address}
      >
        {busy === "register" ? "Staking the bail…" : `Stake ${formatGen(MIN_BAIL)} GEN bail`}
      </button>
    </div>
  );
}
