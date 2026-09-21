import {
  ReactNode,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { createBreakGlassClient } from "../lib/client";
import { BreakGlass } from "../lib/contract";
import { AlarmSummary, Stats, TargetSummary } from "../lib/types";
import { describeError } from "../lib/errors";
import { useWallet } from "../hooks/useWallet";

const EMPTY_STATS: Stats = {
  targets: 0,
  alarms: 0,
  live: 0,
  paused: 0,
  closed: 0,
  totalBail: 0n,
  totalBonds: 0n,
  totalPaid: 0n,
};

interface BreakGlassCtx {
  wallet: ReturnType<typeof useWallet>;
  read: BreakGlass;
  targets: TargetSummary[];
  alarms: AlarmSummary[];
  stats: Stats;
  loading: boolean;
  error: string | null;
  busy: string | null;
  txError: string | null;
  lastTx: string | null;
  version: number;
  refresh: () => void;
  dismissTx: () => void;
  run: (label: string, fn: (c: BreakGlass) => Promise<string>) => Promise<boolean>;
}

const Ctx = createContext<BreakGlassCtx | null>(null);

export function BreakGlassProvider({ children }: { children: ReactNode }) {
  const wallet = useWallet();
  const [targets, setTargets] = useState<TargetSummary[]>([]);
  const [alarms, setAlarms] = useState<AlarmSummary[]>([]);
  const [stats, setStats] = useState<Stats>(EMPTY_STATS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [txError, setTxError] = useState<string | null>(null);
  const [lastTx, setLastTx] = useState<string | null>(null);
  const [version, setVersion] = useState(0);

  const readClient = useMemo(() => new BreakGlass(createBreakGlassClient()), []);
  const writeClient = useMemo(
    () => new BreakGlass(createBreakGlassClient(wallet.address)),
    [wallet.address],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [t, a, s] = await Promise.all([
        readClient.listTargets(0, 100),
        readClient.listAlarms(0, 100, 0),
        readClient.getStats(),
      ]);
      setTargets(t);
      setAlarms(a);
      setStats(s);
    } catch (e) {
      setError(describeError(e));
    } finally {
      setLoading(false);
    }
  }, [readClient]);

  useEffect(() => {
    load();
  }, [load, version]);

  const refresh = useCallback(() => setVersion((v) => v + 1), []);

  const run = useCallback(
    async (label: string, fn: (c: BreakGlass) => Promise<string>) => {
      setBusy(label);
      setTxError(null);
      setLastTx(null);
      try {
        const txHash = await fn(writeClient);
        await writeClient.waitForReceipt(txHash);
        setLastTx(txHash);
        refresh();
        return true;
      } catch (e) {
        setTxError(describeError(e));
        return false;
      } finally {
        setBusy(null);
      }
    },
    [writeClient, refresh],
  );

  const dismissTx = useCallback(() => setTxError(null), []);

  const value: BreakGlassCtx = {
    wallet,
    read: readClient,
    targets,
    alarms,
    stats,
    loading,
    error,
    busy,
    txError,
    lastTx,
    version,
    refresh,
    dismissTx,
    run,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useBreakGlass(): BreakGlassCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useBreakGlass must be used inside BreakGlassProvider");
  return ctx;
}
