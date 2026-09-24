import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useBreakGlass } from "../context/BreakGlassContext";
import { AlarmLamp, TargetLamp } from "../components/StatusLamp";
import { VerdictPlate } from "../components/VerdictPlate";
import { Alarm, Target } from "../lib/types";
import {
  ALARM_BOND,
  EXPLORER_ADDR,
  formatClock,
  formatGen,
  hexAddr,
  hostOf,
  shortAddr,
} from "../config";

export function TargetPage() {
  const { id } = useParams();
  const { read, wallet, run, busy, refresh } = useBreakGlass();
  const tid = Number(id);

  const [target, setTarget] = useState<Target | null>(null);
  const [alarms, setAlarms] = useState<Alarm[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [nonce, setNonce] = useState<string | null>(null);
  const [fixUrl, setFixUrl] = useState("");
  const [fixNote, setFixNote] = useState("");

  const load = async () => {
    try {
      const t = await read.getTarget(tid);
      setTarget(t);
      if (t) {
        const summaries = await read.listAlarms(0, 50, tid);
        const rows = await Promise.all(summaries.map((s) => read.getAlarm(s.id)));
        setAlarms(rows.filter(Boolean) as Alarm[]);
      }
      setErr(null);
    } catch (e: any) {
      setErr(e?.message ?? "Could not load this target.");
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tid]);

  if (err) return <p className="note bad">{err}</p>;
  if (!target) return <p className="note">Reading the target…</p>;

  const isOwner =
    wallet.address && target.owner.toLowerCase() === wallet.address.toLowerCase();
  const openAlarm = alarms.find((a) => a.status === "PENDING");

  const close = async () => {
    if (await run(`close-${tid}`, (c) => c.closeTarget(tid))) refresh();
  };

  return (
    <div className="detail">
      <nav className="crumb">
        <Link to="/">Board</Link> <span>/</span> {target.label}
      </nav>

      <header className={`detail-head ${target.status.toLowerCase()}`}>
        <div>
          <h2>{target.label}</h2>
          <p className="mono row-sub">
            <a href={EXPLORER_ADDR(hexAddr(target.contractAddr))} target="_blank" rel="noreferrer">
              {hexAddr(target.contractAddr)}
            </a>
            {" · "}
            <a href={target.archiveUrl} target="_blank" rel="noreferrer">
              {hostOf(target.archiveUrl)}
            </a>
          </p>
          <p className="row-sub">
            owner <span className="mono">{shortAddr(target.owner)}</span>
            {" · registered "}
            {formatClock(target.createdAt)}
          </p>
        </div>
        <div className="detail-side">
          <TargetLamp status={target.status} />
          <span className="mono bail">{formatGen(target.bail)} GEN bail</span>
          {target.lastFixHash && (
            <span className="mono dim">last fix {target.lastFixHash}</span>
          )}
        </div>
      </header>

      {isOwner && target.status === "LIVE" && openAlarm && (
        <p className="note">
          An alarm is open, so the protection stays on and cannot be closed
          until it settles.
        </p>
      )}

      {isOwner && target.status === "LIVE" && !openAlarm && (
        <section className="panel">
          <h3>Owner controls</h3>
          <p className="note">
            Closing ends the protection and returns the bail, including any
            bond a false reporter burned into it. It only works when no alarm
            is open and the target is not paused.
          </p>
          <button className="btn ghost" onClick={close} disabled={busy !== null}>
            {busy === `close-${tid}` ? "Closing…" : "Close protection"}
          </button>
        </section>
      )}

      {target.status === "EXPLOITED" && isOwner && (
        <section className="panel fire">
          <h3>Resume with a fix</h3>
          <p className="note">
            Publish a page showing the concrete fix to this contract (diff,
            patch, or redeployment record, quoting the registered source) and
            naming the contract address {hexAddr(target.contractAddr)}. Stake{" "}
            {formatGen(ALARM_BOND)} GEN, and the validators judge it. The stake
            comes back when the fix holds.
          </p>
          <label className="field">
            <span>Fix page URL</span>
            <input
              value={fixUrl}
              onChange={(e) => setFixUrl(e.target.value)}
              placeholder="https://…/the-fix"
            />
          </label>
          <label className="field">
            <span>What was fixed</span>
            <textarea
              value={fixNote}
              onChange={(e) => setFixNote(e.target.value)}
              rows={3}
              placeholder="The reentrancy guard in withdraw() and where the diff lives"
            />
          </label>
          <button
            className="btn primary"
            disabled={busy !== null || !fixUrl || !fixNote}
            onClick={async () => {
              if (
                await run(`resume-${tid}`, (c) =>
                  c.resume(tid, fixUrl, fixNote, ALARM_BOND),
                )
              ) {
                setFixUrl("");
                setFixNote("");
                load();
              }
            }}
          >
            {busy === `resume-${tid}` ? "Asking the validators…" : "Submit the fix"}
          </button>
        </section>
      )}

      <section className="panel">
        <div className="panel-head">
          <h3>Alarms on this target</h3>
          {openAlarm ? (
            <span className="note">one alarm at a time</span>
          ) : (
            target.status === "LIVE" && (
              <Link className="btn fire small" to={`/targets/${tid}/alarm`}>
                File an alarm
              </Link>
            )
          )}
        </div>
        {alarms.length === 0 ? (
          <p className="note">No alarm has been filed here yet.</p>
        ) : (
          <div className="stack tight">
            {alarms.map((a) => (
              <AlarmCard
                key={a.id}
                alarm={a}
                onNonce={setNonce}
                onSettled={() => {
                  setNonce(null);
                  load();
                }}
              />
            ))}
          </div>
        )}
      </section>

      {nonce && (
        <section className="panel mono nonce-panel">
          <h3>Review nonce, reserved on-chain</h3>
          <p className="note">
            This value is pinned in the contract's storage, so it holds until a
            review consumes it. Write it, and the contract address above, into
            the report page, then run the review. A report without both proves
            nothing.
          </p>
          <code className="nonce">{nonce}</code>
        </section>
      )}
    </div>
  );
}

function AlarmCard({
  alarm,
  onNonce,
  onSettled,
}: {
  alarm: Alarm;
  onNonce: (n: string) => void;
  onSettled: () => void;
}) {
  const { read, run, busy } = useBreakGlass();

  const reserve = async () => {
    // Reserve first, present second: the displayed value is the pinned one,
    // written into the contract's storage by this very transaction.
    if (await run(`reserve-${alarm.id}`, (c) => c.reserveReviewNonce(alarm.id))) {
      const n = await read.alarmReviewNonce(alarm.id);
      onNonce(n);
    }
  };

  const review = async () => {
    if (await run(`review-${alarm.id}`, (c) => c.reviewAlarm(alarm.id))) {
      onSettled();
    }
  };

  return (
    <article className={`row alarm ${alarm.status.toLowerCase()}`}>
      <div className="row-main">
        <AlarmLamp status={alarm.status} />
        <p className="row-reason">{alarm.reason}</p>
        <p className="row-sub">
          <a href={alarm.reportUrl} target="_blank" rel="noreferrer">
            report on {hostOf(alarm.reportUrl)}
          </a>
          {" · reporter "}
          <span className="mono">{shortAddr(alarm.reporter)}</span>
          {" · "}
          {formatClock(alarm.createdAt)}
        </p>
      </div>
      <div className="row-side">
        <span className="mono bail">{formatGen(alarm.bond)} GEN bond</span>
        {alarm.status === "PENDING" && (
          <div className="btn-row">
            <button className="btn primary small" onClick={reserve} disabled={busy !== null}>
              {busy === `reserve-${alarm.id}` ? "Reserving…" : "Reserve the review nonce"}
            </button>
            <button className="btn ghost small" onClick={review} disabled={busy !== null}>
              {busy === `review-${alarm.id}` ? "Reviewing…" : "Run the review"}
            </button>
          </div>
        )}
      </div>
      <VerdictPlate alarm={alarm} />
    </article>
  );
}
