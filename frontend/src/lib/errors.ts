/** Contract reverts and wallet failures, translated into next-step guidance. */

const RULES: Array<[RegExp, string]> = [
  [/bail is below/i, "The bail is below the 0.1 GEN minimum. Send more with the registration."],
  [/bond must match/i, "The alarm bond must be 0.01 GEN. Send it with the alarm."],
  [/resume carries the alarm bond/i, "Resuming costs 0.01 GEN, refunded when the fix holds. Send it with the resume."],
  [/owner cannot alarm its own/i, "The target owner cannot alarm their own contract. A third party files the alarm."],
  [/already has an alarm/i, "This target already has an alarm awaiting review. One at a time."],
  [/only accepted on a live target/i, "Alarms land on live targets only. This one is paused or closed."],
  [/only the target owner can resume/i, "Only the target owner can submit a fix."],
  [/the target is not paused/i, "The target is not paused, so there is nothing to resume."],
  [/only the target owner can close/i, "Only the target owner can close the protection."],
  [/resume the target before closing/i, "Settle the exploit first: resume with a fix, then close."],
  [/settle the open alarm/i, "An alarm is still open on this target. Wait for its review."],
  [/already closed/i, "This target is already closed."],
  [/not awaiting a review/i, "This alarm is not awaiting review. It already settled."],
  [/retry window is still closed/i, "The last review just failed. The retry window opens one hour after it."],
  [/review budget/i, "The review budget is spent. The alarm expired and the bond went home."],
  [/no clear verdict/i, "The reviewers returned no clear verdict. Trigger the review again."],
  [/unreadable output/i, "The reviewers returned unreadable output. Trigger the review again."],
  [/did not accept the fix/i, "The reviewers rejected the fix. Publish a concrete diff or redeployment record, then resume again."],
  [/report_url|fix_url|archive_url/i, "The URL must be a public http(s) page, 500 characters at most."],
  [/label: 1-120/i, "The label needs 1 to 120 characters."],
  [/reason: 1-2000|note: 1-2000/i, "Keep the text between 1 and 2000 characters."],
  [/user rejected/i, "The request was rejected in the wallet."],
  [/insufficient funds/i, "The wallet does not cover the amount plus gas."],
  [/chain|network/i, "The wallet is on the wrong network. Switch to GenLayer StudioNet."],
];

export function describeError(e: unknown): string {
  const raw =
    typeof e === "string"
      ? e
      : ((e as any)?.message ?? (e as any)?.shortMessage ?? String(e));
  const text = String(raw);

  for (const [pattern, friendly] of RULES) {
    if (pattern.test(text)) return friendly;
  }

  if (/fetch|network|timeout/i.test(text)) {
    return "The network did not answer. Check the connection and try again.";
  }
  const match = text.match(/UserError[^"]*"([^"]{3,160})"/);
  if (match) return match[1];
  const quoted = text.match(/"([^"]{10,160})"/);
  if (quoted) return quoted[1];
  return text.slice(0, 200) || "Something went wrong. Try again.";
}
