import type { Metadata } from "next";
import Nav from "@/components/Nav";
import "./globals.css";

export const metadata: Metadata = {
  title: "Aegis-MCP Dashboard",
  description: "Read-only security console for the aegis-mcp serve API"
};

export default function RootLayout({
  children
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <Nav />
        <main className="main">{children}</main>
      </body>
    </html>
  );
}
