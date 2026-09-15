const TONE: Record<string, string> = {
  ALLOW: "good",
  DENY: "bad",
  WARN: "warn",
  REQUIRE_APPROVAL: "warn",
  SANDBOX: "info",
  APPROVED: "good",
  DENIED: "bad",
  PENDING: "warn",
  EXPIRED: "muted",
  OPEN: "bad",
  ACKNOWLEDGED: "warn",
  MITIGATED: "warn",
  RESOLVED: "good",
  FALSE_POSITIVE: "muted",
  CRITICAL: "bad",
  HIGH: "bad",
  MEDIUM: "warn",
  LOW: "info"
};

export default function Badge({ value }: { value: string }) {
  const tone = TONE[value] ?? "muted";
  return <span className={`badge badge-${tone}`}>{value}</span>;
}
