"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const LINKS = [
  { href: "/overview", label: "Overview" },
  { href: "/tools", label: "Tools" },
  { href: "/tool-changes", label: "Tool changes" },
  { href: "/events", label: "Events" },
  { href: "/incidents", label: "Incidents" },
  { href: "/policies", label: "Policies" },
  { href: "/approvals", label: "Approvals" },
  { href: "/taint", label: "Taint" },
  { href: "/audit", label: "Audit" },
  { href: "/settings", label: "Settings" }
];

export default function Nav() {
  const pathname = usePathname();
  return (
    <nav className="nav">
      <div className="nav-brand">Aegis-MCP</div>
      <div className="nav-links">
        {LINKS.map((l) => (
          <Link
            key={l.href}
            href={l.href}
            className={pathname === l.href ? "nav-link active" : "nav-link"}
          >
            {l.label}
          </Link>
        ))}
      </div>
    </nav>
  );
}
