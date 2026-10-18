const nodes = [
  { name: "target",   role: "SSH server (victim)",      ip: "172.30.0.10", status: "online",  note: "Parser watching auth.log" },
  { name: "peer",     role: "Neighbour node",           ip: "172.30.0.11", status: "online",  note: "No alerts" },
  { name: "attacker", role: "Kali (attack simulator)",  ip: "172.30.0.12", status: "blocked", note: "Blocked by city_blacklist" },
];

const colors = { online: "#1f9d55", blocked: "#d64545", warning: "#e0a526" };

export default function Home() {
  return (
    <main style={{ padding: 32, fontFamily: "system-ui, sans-serif", background: "#0f1115", minHeight: "100vh", color: "#e6e6e6" }}>
      <h1 style={{ marginBottom: 4 }}>DUAL-SHIELD</h1>
      <p style={{ marginTop: 0, color: "#9aa0a6" }}>Node status (dummy data)</p>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 16, marginTop: 24 }}>
        {nodes.map((n) => (
          <div key={n.name} style={{ background: "#1a1d23", borderRadius: 12, padding: 20, borderLeft: `6px solid ${colors[n.status]}` }}>
            <h2 style={{ margin: 0 }}>{n.name}</h2>
            <p style={{ margin: "4px 0 12px", color: "#9aa0a6" }}>{n.role}</p>
            <p style={{ margin: "2px 0" }}>IP: {n.ip}</p>
            <p style={{ margin: "2px 0" }}>
              Status: <strong style={{ color: colors[n.status] }}>{n.status.toUpperCase()}</strong>
            </p>
            <p style={{ margin: "12px 0 0", fontSize: 14, color: "#9aa0a6" }}>{n.note}</p>
          </div>
        ))}
      </div>
    </main>
  );
}
