"use client";
import { useState } from "react";

export default function LoginForm() {
  const [pw, setPw] = useState(""), [msg, setMsg] = useState(""), [busy, setBusy] = useState(false);
  async function submit(e) {
    e.preventDefault(); setBusy(true); setMsg("");
    try {
      const r = await fetch("/api/auth/login", { method: "POST", headers: { "content-type": "application/json", "x-ds-confirm": "1" }, body: JSON.stringify({ password: pw }) });
      const j = await r.json();
      if (j.ok) { window.location.href = "/"; return; }
      setMsg(j.error || "Sign in failed."); setPw("");
    } catch { setMsg("Server not reachable."); }
    setBusy(false);
  }
  return (
    <main className="loginWrap">
      <form className="loginCard" onSubmit={submit} autoComplete="off">
        <div className="logo">DS</div>
        <h1>Dual-Shield</h1>
        <p className="muted">Operator console. Sign in with the administrator or the read-only viewer password.</p>
        <label htmlFor="pw">Password</label>
        <input id="pw" type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoFocus required minLength={8} maxLength={200} />
        <button disabled={busy || pw.length < 8}>{busy ? "Checking..." : "Sign in"}</button>
        {msg && <div className="err" role="alert">{msg}</div>}
        <p className="tiny">Repeated wrong passwords lock this screen for a while. Every sign-in is written to a tamper-evident audit log.</p>
      </form>
    </main>
  );
}
