import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useBreakGlass } from "../context/BreakGlassContext";
import { TargetLamp } from "../components/StatusLamp";
import { Target } from "../lib/types";
import { formatGen, hexAddr, hostOf, shortAddr, EXPLORER_ADDR } from "../config";

export function Board() {
  const { read, targets, loading, error, version } = useBreakGlass();
  const [full, setFull] = useState<Target[]>([]);
  const [loadErr, setLoadErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const rows = await Promise.all(targets.map((t) => read.getTarget(t.id)));
        if (alive) setFull(rows.filter(Boolean) as Target[]);
        setLoadErr(null);
      } catch (e: any) {
        if (alive) setLoadErr(e?.message ?? "Could not load the targets.");
      }
    })();
    return () => {
      alive = false;
    };
  }, [read, targets, version]);

  if (loading && full.length === 0) {
    return <p className="note">Reading the breaker…</p>;
  }
  if (error || loadErr) {
    return (
      <>
        <PageHead />
        <p className="note bad">{error ?? loadErr}</p>
      </>
    );
  }
  if (full.length === 0) {
    return (
      <>
        <PageHead />
        <div className="empty">
          <p>No contract is under the breaker yet.</p>
          <Link className="btn primary" to="/register">
            Put a contract under it
          </Link>
        </div>
      </>
    );
  }

  return (
    <>
      <PageHead />
      <div className="stack">
      {full.map((t) => (
        <article key={t.id} className={`row target ${t.status.toLowerCase()}`}>
          <div className="row-main">
            <h3>
              <Link to={`/targets/${t.id}`}>{t.label}</Link>
            </h3>
            <p className="row-sub mono">
              <a href={EXPLORER_ADDR(hexAddr(t.contractAddr))} target="_blank" rel="noreferrer">
                {shortAddr(t.contractAddr)}
              </a>
              {" · "}
              {hostOf(t.archiveUrl)}
            </p>
          </div>
          <div className="row-side">
            <TargetLamp status={t.status} />
            <span className="mono bail">{formatGen(t.bail)} GEN bail</span>
          </div>
        </article>
      ))}
      </div>
    </>
  );
}

function PageHead() {
  return (
    <header className="page-head">
      <h2>Targets under the breaker</h2>
      <p className="note">
        Every row is a live contract that pauses itself when someone proves an
        exploit against it.
      </p>
    </header>
  );
}
