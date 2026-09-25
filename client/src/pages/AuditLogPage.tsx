import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import axios from "axios";
import { ArrowLeft, ShieldOff, Search, Activity } from "lucide-react";
import { auditLogsApi } from "../api/auditLogs";
import { extractErrorMessage } from "../lib/errors";
import { VaultMark } from "../components/VaultMark";
import { Field } from "../components/ui/Field";
import { Button } from "../components/ui/Button";
import type { AuditLog } from "../types";

function resultTone(result: string) {
  const r = result.toLowerCase();
  if (r.includes("success") || r.includes("ok")) return "text-success border-success/30";
  if (r.includes("fail") || r.includes("denied") || r.includes("error")) return "text-danger border-danger/30";
  return "text-text-muted border-line";
}

export default function AuditLogPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [totalCount, setTotalCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [forbidden, setForbidden] = useState(false);
  const [error, setError] = useState("");

  const [userIdFilter, setUserIdFilter] = useState("");
  const [filtering, setFiltering] = useState(false);

  const loadRecent = async () => {
    setLoading(true);
    setError("");
    setForbidden(false);
    try {
      const [logsRes, countRes] = await Promise.all([
        auditLogsApi.getRecent(100),
        auditLogsApi.getCount(),
      ]);
      if (logsRes.data.success && logsRes.data.data) setLogs(logsRes.data.data);
      if (countRes.data.success && typeof countRes.data.data === "number") setTotalCount(countRes.data.data);
    } catch (err) {
      if (axios.isAxiosError(err) && err.response?.status === 403) {
        setForbidden(true);
      } else {
        setError(extractErrorMessage(err, "Could not load audit logs."));
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRecent();
  }, []);

  const handleFilterByUser = async () => {
    if (!userIdFilter.trim()) {
      await loadRecent();
      return;
    }
    setFiltering(true);
    setError("");
    try {
      const res = await auditLogsApi.getByUser(userIdFilter.trim());
      if (res.data.success && res.data.data) setLogs(res.data.data);
    } catch (err) {
      if (axios.isAxiosError(err) && err.response?.status === 403) {
        setForbidden(true);
      } else {
        setError(extractErrorMessage(err, "Could not load logs for that user ID."));
      }
    } finally {
      setFiltering(false);
    }
  };

  return (
    <div className="min-h-screen">
      <header className="border-b border-line glass sticky top-0 z-10">
        <div className="max-w-4xl mx-auto px-6 py-4 flex items-center justify-between">
          <Link to="/dashboard" className="flex items-center gap-2.5 text-text hover:text-accent transition-colors">
            <ArrowLeft size={16} />
            <VaultMark size={22} />
            <span className="font-medium tracking-tight text-sm">VaultGuard</span>
          </Link>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-10">
        <div className="flex items-end justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-medium text-text">Audit trail</h1>
            <p className="text-sm text-text-muted mt-1">
              {totalCount !== null ? `${totalCount} total events recorded` : "Security and access history"}
            </p>
          </div>
        </div>

        {forbidden ? (
          <div className="glass border border-line rounded-2xl px-6 py-14 text-center space-y-3">
            <ShieldOff size={28} className="mx-auto text-text-faint" />
            <h2 className="text-sm font-medium text-text">Restricted to Admin and Auditor roles</h2>
            <p className="text-sm text-text-muted max-w-md mx-auto">
              Your account does not currently have permission to view the audit trail. This
              endpoint is limited to accounts with the <span className="font-mono text-accent">Admin</span> or{" "}
              <span className="font-mono text-accent">Auditor</span> role.
            </p>
          </div>
        ) : (
          <>
            <div className="glass border border-line rounded-2xl p-4 mb-6 flex flex-col sm:flex-row gap-3 items-stretch sm:items-end">
              <div className="flex-1">
                <Field
                  label="Filter by user ID"
                  value={userIdFilter}
                  onChange={(e) => setUserIdFilter(e.target.value)}
                  placeholder="paste a user GUID, or leave blank for recent activity"
                />
              </div>
              <Button onClick={handleFilterByUser} disabled={filtering} className="gap-1.5 shrink-0">
                <Search size={15} />
                {filtering ? "Searching…" : "Search"}
              </Button>
            </div>

            {error && (
              <div className="mb-6 text-sm text-danger bg-danger/10 border border-danger/25 rounded-xl px-3.5 py-2.5">
                {error}
              </div>
            )}

            {loading ? (
              <p className="text-sm text-text-muted">Loading…</p>
            ) : logs.length === 0 ? (
              <div className="border border-dashed border-line rounded-2xl px-6 py-14 text-center">
                <Activity size={22} className="mx-auto text-text-faint mb-2" />
                <p className="text-sm text-text-muted">No events found.</p>
              </div>
            ) : (
              <div className="space-y-2">
                {logs.map((log) => (
                  <div
                    key={log.id}
                    className="glass border border-line rounded-xl px-4 py-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-sm"
                  >
                    <span className="font-mono text-xs text-text-faint w-40 shrink-0">
                      {new Date(log.timestamp).toLocaleString()}
                    </span>
                    <span className="text-text font-medium">{log.action}</span>
                    <span className="text-text-muted text-xs">{log.entityName}</span>
                    <span className={`text-xs border rounded-full px-2 py-0.5 ml-auto ${resultTone(log.result)}`}>
                      {log.result}
                    </span>
                    <span className="font-mono text-xs text-text-faint">{log.ipAddress}</span>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}