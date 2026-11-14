import "./globals.css";

// No web fonts: nothing is fetched from the internet (works offline in the lab and keeps the CSP strict).
export const metadata = {
  title: "Dual-Shield",
  description: "Two-layer defence: network consensus on Hyperledger Fabric and ransomware recovery",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
