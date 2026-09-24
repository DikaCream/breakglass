export type TargetStatus = "LIVE" | "EXPLOITED" | "CLOSED";
export type AlarmStatus = "PENDING" | "VALID" | "REJECTED" | "EXPIRED";

export interface Target {
  id: number;
  owner: string;
  contractAddr: string;
  label: string;
  archiveUrl: string;
  bail: bigint;
  status: TargetStatus;
  activeAlarmId: number;
  lastFixHash: string;
  createdAt: number;
}

export interface Alarm {
  id: number;
  targetId: number;
  reporter: string;
  reportUrl: string;
  reason: string;
  bond: bigint;
  status: AlarmStatus;
  verdict: string;
  reasoning: string;
  fixHash: string;
  rounds: number;
  failedAttempts: number;
  lastAttemptAt: number;
  createdAt: number;
  settledAt: number;
}

export interface TargetSummary {
  id: number;
  label: string;
  status: TargetStatus;
  contractAddr: string;
}

export interface AlarmSummary {
  id: number;
  targetId: number;
  status: AlarmStatus;
}

export interface ConsentInfo {
  breaker: string;
  owner: string;
  closed: boolean;
}

export interface Stats {
  targets: number;
  alarms: number;
  live: number;
  paused: number;
  closed: number;
  totalBail: bigint;
  totalBonds: bigint;
  totalBailIn: bigint;
  totalBailOut: bigint;
  totalBondsIn: bigint;
  totalBondsOut: bigint;
  totalBurned: bigint;
  totalPaid: bigint;
  bailConsistent: boolean;
  bondsConsistent: boolean;
}

function addr(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "object") {
    const anyV = v as Record<string, unknown>;
    if ("as_hex" in anyV) return String(anyV.as_hex);
    if ("_as_hex" in anyV) return String(anyV._as_hex);
    if ("hex" in anyV) return String(anyV.hex);
    if ("0" in anyV && "1" in anyV) return "";
  }
  return String(v);
}

export { addr };

function big(v: unknown): bigint {
  try {
    if (typeof v === "bigint") return v;
    if (typeof v === "string") return v.startsWith("addr#") ? 0n : BigInt(v);
    if (typeof v === "number") return BigInt(v);
  } catch {
    /* keep 0 */
  }
  return 0n;
}

function num(v: unknown): number {
  return Number(big(v));
}

export function toTarget(v: any): Target {
  return {
    id: num(v.id),
    owner: addr(v.owner),
    contractAddr: addr(v.contract_addr),
    label: String(v.label ?? ""),
    archiveUrl: String(v.archive_url ?? ""),
    bail: big(v.bail),
    status: (String(v.status ?? "LIVE") as TargetStatus),
    activeAlarmId: num(v.active_alarm_id),
    lastFixHash: String(v.last_fix_hash ?? ""),
    createdAt: num(v.created_at),
  };
}

export function toAlarm(v: any): Alarm {
  return {
    id: num(v.id),
    targetId: num(v.target_id),
    reporter: addr(v.reporter),
    reportUrl: String(v.report_url ?? ""),
    reason: String(v.reason ?? ""),
    bond: big(v.bond),
    status: (String(v.status ?? "PENDING") as AlarmStatus),
    verdict: String(v.verdict ?? ""),
    reasoning: String(v.reasoning ?? ""),
    fixHash: String(v.fix_hash ?? ""),
    rounds: num(v.rounds),
    failedAttempts: num(v.failed_attempts),
    lastAttemptAt: num(v.last_attempt_at),
    createdAt: num(v.created_at),
    settledAt: num(v.settled_at),
  };
}

export function toTargetSummary(v: any): TargetSummary {
  return {
    id: num(v.id),
    label: String(v.label ?? ""),
    status: String(v.status ?? "LIVE") as TargetStatus,
    contractAddr: addr(v.contract_addr),
  };
}

export function toAlarmSummary(v: any): AlarmSummary {
  return {
    id: num(v.id),
    targetId: num(v.target_id),
    status: String(v.status ?? "PENDING") as AlarmStatus,
  };
}

export function toStats(v: any): Stats {
  return {
    targets: num(v.targets),
    alarms: num(v.alarms),
    live: num(v.live),
    paused: num(v.paused),
    closed: num(v.closed),
    totalBail: big(v.total_bail),
    totalBonds: big(v.total_bonds),
    totalBailIn: big(v.total_bail_in),
    totalBailOut: big(v.total_bail_out),
    totalBondsIn: big(v.total_bonds_in),
    totalBondsOut: big(v.total_bonds_out),
    totalBurned: big(v.total_burned),
    totalPaid: big(v.total_paid),
    bailConsistent: Boolean(v.bail_consistent),
    bondsConsistent: Boolean(v.bonds_consistent),
  };
}

export const STATUS_LABEL: Record<string, string> = {
  LIVE: "protected",
  EXPLOITED: "paused",
  CLOSED: "closed",
  PENDING: "awaiting review",
  VALID: "exploit confirmed",
  REJECTED: "alarm rejected",
  EXPIRED: "review budget spent",
};
