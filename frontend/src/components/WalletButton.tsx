import { useBreakGlass } from "../context/BreakGlassContext";
import { formatGen, shortAddr } from "../config";

export function WalletButton() {
  const { wallet } = useBreakGlass();

  if (!wallet.hasProvider) {
    return (
      <a
        className="btn ghost small"
        href="https://metamask.io/download/"
        target="_blank"
        rel="noreferrer"
      >
        Install a wallet
      </a>
    );
  }

  if (wallet.address) {
    return (
      <span className="wallet-chip" title={wallet.address}>
        <span className="mono">{formatGen(wallet.balance)} GEN</span>
        <span className="mono addr">{shortAddr(wallet.address)}</span>
      </span>
    );
  }

  return (
    <button className="btn primary small" onClick={wallet.connect} disabled={wallet.busy}>
      {wallet.busy ? "Connecting…" : "Connect wallet"}
    </button>
  );
}
