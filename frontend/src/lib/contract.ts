import { CONTRACT_ADDRESS } from "../config";
import {
  Alarm,
  AlarmSummary,
  ConsentInfo,
  Stats,
  Target,
  TargetSummary,
  addr,
  toAlarm,
  toAlarmSummary,
  toStats,
  toTarget,
  toTargetSummary,
} from "./types";

export class BreakGlass {
  constructor(private client: any, private address: string = CONTRACT_ADDRESS) {}

  private async read(
    functionName: string,
    args: unknown[] = [],
    at?: string,
  ): Promise<any> {
    return this.client.readContract({
      address: (at ?? this.address) as `0x${string}`,
      functionName,
      args,
    });
  }

  private async write(
    functionName: string,
    args: unknown[],
    value: bigint = 0n,
  ): Promise<string> {
    const txHash = await this.client.writeContract({
      address: this.address as `0x${string}`,
      functionName,
      args,
      value,
    });
    return txHash as string;
  }

  async waitForReceipt(txHash: string, retries = 70, interval = 3000): Promise<any> {
    return this.client.waitForTransactionReceipt({
      hash: txHash,
      status: "ACCEPTED" as any,
      retries,
      interval,
    });
  }

  // ---- reads ----------------------------------------------------------
  async getStats(): Promise<Stats> {
    return toStats(await this.read("get_stats"));
  }

  async getTarget(id: number): Promise<Target | null> {
    const v = await this.read("get_target", [id]);
    if (v == null) return null;
    return toTarget(v);
  }

  async getAlarm(id: number): Promise<Alarm | null> {
    const v = await this.read("get_alarm", [id]);
    if (v == null) return null;
    return toAlarm(v);
  }

  async listTargets(offset = 0, limit = 50): Promise<TargetSummary[]> {
    const v = await this.read("list_targets", [offset, limit]);
    return Array.isArray(v) ? v.map(toTargetSummary) : [];
  }

  async listAlarms(
    offset = 0,
    limit = 50,
    targetId = 0,
  ): Promise<AlarmSummary[]> {
    const v = await this.read("list_alarms", [offset, limit, targetId]);
    return Array.isArray(v) ? v.map(toAlarmSummary) : [];
  }

  async isPaused(contractAddrHex: string): Promise<boolean> {
    return Boolean(await this.read("is_paused", [contractAddrHex]));
  }

  async alarmReviewNonce(alarmId: number): Promise<string> {
    return String(await this.read("alarm_review_nonce", [alarmId]));
  }

  /** What the target contract reports about its own registration. */
  async breakglassRegistration(contractAddrHex: string): Promise<ConsentInfo | null> {
    try {
      const v = await this.read("breakglass_registration", [], contractAddrHex);
      if (v == null) return null;
      return { breaker: addr(v.breaker), owner: addr(v.owner), closed: Boolean(v.closed) };
    } catch {
      return null;
    }
  }

  // ---- writes ---------------------------------------------------------
  async registerTarget(
    contractAddrHex: string,
    label: string,
    archiveUrl: string,
    bail: bigint,
  ): Promise<string> {
    return this.write("register_target", [contractAddrHex, label, archiveUrl], bail);
  }

  async fileAlarm(targetId: number, reportUrl: string, reason: string, bond: bigint): Promise<string> {
    return this.write("file_alarm", [targetId, reportUrl, reason], bond);
  }

  async reserveReviewNonce(alarmId: number): Promise<string> {
    return this.write("reserve_review_nonce", [alarmId]);
  }

  async reviewAlarm(alarmId: number): Promise<string> {
    return this.write("review_alarm", [alarmId]);
  }

  async resume(targetId: number, fixUrl: string, note: string, bond: bigint): Promise<string> {
    return this.write("resume", [targetId, fixUrl, note], bond);
  }

  async closeTarget(targetId: number): Promise<string> {
    return this.write("close_target", [targetId]);
  }
}
