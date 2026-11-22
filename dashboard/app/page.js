import AdminConsole from "./AdminConsole";
export const metadata = { title: "Dual-Shield console" };
export const dynamic = "force-dynamic";     // rendered per request: needed so Next.js can stamp the CSP nonce on its scripts
export default function Home() { return <AdminConsole />; }
