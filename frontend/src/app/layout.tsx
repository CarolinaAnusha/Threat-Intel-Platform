import type { Metadata } from "next";
// @ts-ignore: side-effect CSS import for global styles
import "./globals.css";

export const metadata: Metadata = {
  title: "Threat Intelligence Platform",
  description: "AI-Powered Threat Intelligence Platform",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}