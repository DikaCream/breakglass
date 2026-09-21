import { Link, NavLink, Route, Routes } from "react-router-dom";
import { BreakGlassProvider, useBreakGlass } from "./context/BreakGlassContext";
import { WalletButton } from "./components/WalletButton";
import { Board } from "./pages/Board";
import { TargetPage } from "./pages/TargetPage";
import { Register } from "./pages/Register";
import { FileAlarm } from "./pages/FileAlarm";
import { HowItWorks } from "./pages/HowItWorks";
import { EXPLORER_TX, formatGen, shortAddr } from "./config";

function Bar() {
  const { stats } = useBreakGlass();

  return (
    <header className="bar">
      <Link to="/" className="brand">
        <span className="brand-mark" aria-hidden="true">
          ⏛
        </span>
        <span className="brand-text">
          <strong>BreakGlass</strong>
          <em>the contract that pulls its own brakes</em>
        </span>
      </Link>

      <nav className="bar-nav" aria-label="Main">
        <NavLink to="/" end className={({ isActive }) => (isActive ? "on" : "")}>
          Targets
        </NavLink>
        <NavLink to="/register" className={({ isActive }) => (isActive ? "on" : "")}>
          Protect a contract
        </NavLink>
        <NavLink to="/how" className={({ isActive }) => (isActive ? "on" : "")}>
          How it works
        </NavLink>
      </nav>

      <div className="bar-meters" aria-label="Live contract state">
        <span className="mini">
          <i className="lamp-dot live" aria-hidden="true" />
          {stats.live} protected
        </span>
        <span className="mini">
          <i className="lamp-dot paused" aria-hidden="true" />
          {stats.paused} paused
        </span>
        <span className="mini mono">{formatGen(stats.totalBail)} GEN bail held</span>
        <span className="mini mono">{formatGen(stats.totalPaid)} GEN paid out</span>
      </div>

      <WalletButton />
    </header>
  );
}

function TxBanner() {
  const { txError, lastTx, dismissTx } = useBreakGlass();
  if (!txError && !lastTx) return null;
  return (
    <div className={`banner ${txError ? "bad" : "good"}`} role="status">
      <span>{txError ?? "The transaction landed."}</span>
      {lastTx && !txError && (
        <a href={EXPLORER_TX(lastTx)} target="_blank" rel="noreferrer" className="mono">
          {shortAddr(lastTx)}
        </a>
      )}
      <button className="x" onClick={dismissTx} aria-label="Dismiss">
        ×
      </button>
    </div>
  );
}

function Footer() {
  const { stats, error } = useBreakGlass();
  return (
    <footer className="foot">
      <span>
        {stats.targets} target{stats.targets === 1 ? "" : "s"} under the breaker ·{" "}
        {stats.alarms} alarm{stats.alarms === 1 ? "" : "s"} filed
      </span>
      {error && <span className="bad">contract unreadable: {error}</span>}
    </footer>
  );
}

export default function App() {
  return (
    <BreakGlassProvider>
      <div className="shell">
        <Bar />
        <TxBanner />
        <main>
          <Routes>
            <Route path="/" element={<Board />} />
            <Route path="/targets/:id" element={<TargetPage />} />
            <Route path="/targets/:id/alarm" element={<FileAlarm />} />
            <Route path="/register" element={<Register />} />
            <Route path="/how" element={<HowItWorks />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </BreakGlassProvider>
  );
}
