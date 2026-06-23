import { useEffect, useState } from "react";

// Minimal shell: confirms the frontend can reach the backend. Real screens
// (estimating, orders, job tickets, shop-floor tracking) come later.

interface Readiness {
  status: string;
  database: boolean;
  redis: boolean;
}

type Probe =
  | { state: "loading" }
  | { state: "ok"; data: Readiness }
  | { state: "error"; message: string };

export function App() {
  const [probe, setProbe] = useState<Probe>({ state: "loading" });

  useEffect(() => {
    let cancelled = false;
    fetch("/health/ready")
      .then((res) => res.json() as Promise<Readiness>)
      .then((data) => {
        if (!cancelled) setProbe({ state: "ok", data });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setProbe({ state: "error", message: String(err) });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <main>
      <h1>🖨️ Printing ERP</h1>
      <p>Print MIS/ERP — quote → order → job ticket → shop floor → delivery.</p>
      <section className="card">
        <h2>Backend status</h2>
        {probe.state === "loading" && <p>Checking…</p>}
        {probe.state === "error" && (
          <p className="bad">Cannot reach backend: {probe.message}</p>
        )}
        {probe.state === "ok" && (
          <ul>
            <li>Overall: {probe.data.status}</li>
            <li>Database: {probe.data.database ? "up" : "down"}</li>
            <li>Redis: {probe.data.redis ? "up" : "down"}</li>
          </ul>
        )}
      </section>
    </main>
  );
}
