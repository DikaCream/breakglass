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
        Stake {formatGen(MIN_BAIL)} GEN as bail and name an archive URL where the
        deployed source lives. From the first block on, an accepted exploit
        alarm pauses your contract and a quarter of the bail pays the reporter.
      </p>
      {!wallet.address && (
        <p className="note bad">Connect a wallet first. The bail leaves it.</p>
      )}
      <label className="field">
        <span>Protected contract address</span>
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
