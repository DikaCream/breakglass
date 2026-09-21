import { AlarmStatus, STATUS_LABEL, TargetStatus } from "../lib/types";

const TARGET_TONE: Record<string, string> = {
  LIVE: "live",
  EXPLOITED: "paused",
  CLOSED: "closed",
};

const ALARM_TONE: Record<string, string> = {
  PENDING: "pending",
  VALID: "fired",
  REJECTED: "rejected",
  EXPIRED: "rejected",
};

export function TargetLamp({ status }: { status: TargetStatus }) {
  const tone = TARGET_TONE[status] ?? "live";
  return (
    <span className="lamp" title={STATUS_LABEL[status] ?? status}>
      <i className={`lamp-dot ${tone}`} aria-hidden="true" />
      {STATUS_LABEL[status] ?? status}
    </span>
  );
}

export function AlarmLamp({ status }: { status: AlarmStatus }) {
  const tone = ALARM_TONE[status] ?? "pending";
  return (
    <span className="lamp" title={STATUS_LABEL[status] ?? status}>
      <i className={`lamp-dot ${tone}`} aria-hidden="true" />
      {STATUS_LABEL[status] ?? status}
    </span>
  );
}
