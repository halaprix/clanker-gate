import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ClankerGate Policy Builder",
  description: "ABI-aware policy builder for ERC-4337 transaction validators",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
