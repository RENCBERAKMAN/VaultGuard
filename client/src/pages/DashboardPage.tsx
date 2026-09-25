import { useEffect, useState, type FormEvent, type ChangeEvent } from "react";
import { Link } from "react-router-dom";
import Papa from "papaparse";
import {
  Lock,
  LockOpen,
  Pencil,
  Trash2,
  Plus,
  UploadCloud,
  FileSpreadsheet,
  ClipboardList,
  X,
  Check,
  AlertTriangle,
  LogOut,
  ShieldCheck,
  Layers,
  Clock,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { secretsApi } from "../api/secrets";
import { extractErrorMessage } from "../lib/errors";
import { VaultMark } from "../components/VaultMark";
import { Field } from "../components/ui/Field";
import { Button } from "../components/ui/Button";
import type { Secret } from "../types";

const VALID_CATEGORIES = ["Password", "ApiKey", "CreditCard", "Note", "Other"] as const;
type ValidCategory = (typeof VALID_CATEGORIES)[number];

const CATEGORY_OPTIONS = [
  { value: "", label: "Select a category (optional)" },
  { value: "Password", label: "Password" },
  { value: "ApiKey", label: "API Key" },
  { value: "CreditCard", label: "Credit Card" },
  { value: "Note", label: "Note" },
  { value: "Other", label: "Other" },
] as const;

interface EntryForm {
  title: string;
  category: string;
  description: string;
  rawValue: string;
  expiresAt: string;
}

const emptyForm: EntryForm = { title: "", category: "", description: "", rawValue: "", expiresAt: "" };

function toIsoOrUndefined(dateStr: string): string | undefined {
  if (!dateStr) return undefined;
  return new Date(`${dateStr}T23:59:59`).toISOString();
}

function normalizeCategory(raw: string | undefined): ValidCategory | undefined {
  if (!raw) return undefined;
  const clean = raw.trim().toLowerCase().replace(/[\s_-]/g, "");
  const map: Record<string, ValidCategory> = {
    password: "Password",
    pwd: "Password",
    apikey: "ApiKey",
    api: "ApiKey",
    creditcard: "CreditCard",
    card: "CreditCard",
    note: "Note",
    notes: "Note",
    other: "Other",
  };
  return map[clean] ?? "Other";
}

function CategorySelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div className="space-y-1.5">
      <label className="block text-sm text-text-muted">Category</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-xl bg-white border border-line px-3.5 py-2.5 text-sm text-text outline-none transition-all duration-200 focus:border-accent/60 focus:shadow-[0_0_0_4px_rgba(91,141,239,0.15)]"
      >
        {CATEGORY_OPTIONS.map((c) => (
          <option key={c.value} value={c.value}>
            {c.label}
          </option>
        ))}
      </select>
    </div>
  );
}

type PanelId = "none" | "create" | "paste" | "csv";

export default function DashboardPage() {
  const { user, logout } = useAuth();
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [activePanel, setActivePanel] = useState<PanelId>("none");
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [revealingId, setRevealingId] = useState<string | null>(null);

  const [createForm, setCreateForm] = useState<EntryForm>(emptyForm);
  const [creating, setCreating] = useState(false);

  const [editingId, setEditingId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<EntryForm>(emptyForm);
  const [saving, setSaving] = useState(false);

  // Paste-based bulk import
  const [bulkText, setBulkText] = useState("");
  const [bulkSubmitting, setBulkSubmitting] = useState(false);
  const [bulkResult, setBulkResult] = useState<{ ok: number; failed: number; errors: string[] } | null>(null);

  // CSV-based import
  const [csvFileName, setCsvFileName] = useState("");
  const [csvColumns, setCsvColumns] = useState<string[]>([]);
  const [csvRows, setCsvRows] = useState<Record<string, string>[]>([]);
  const [csvMapping, setCsvMapping] = useState({ title: "", category: "", value: "" });
  const [csvImporting, setCsvImporting] = useState(false);
  const [csvResult, setCsvResult] = useState<{ ok: number; failed: number; errors: string[] } | null>(null);
  const [csvParseError, setCsvParseError] = useState("");

  const loadSecrets = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await secretsApi.getAll();
      if (res.data.success && res.data.data) {
        setSecrets(res.data.data);
      }
    } catch (err) {
      setError(extractErrorMessage(err, "Could not load the vault registry."));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSecrets();
  }, []);

  useEffect(() => {
    if (!notice) return;
    const t = setTimeout(() => setNotice(""), 3000);
    return () => clearTimeout(t);
  }, [notice]);

  const closePanels = () => {
    setActivePanel("none");
    setCreateForm(emptyForm);
    setBulkText("");
    setBulkResult(null);
    setCsvFileName("");
    setCsvColumns([]);
    setCsvRows([]);
    setCsvMapping({ title: "", category: "", value: "" });
    setCsvResult(null);
    setCsvParseError("");
  };

  // ---------- Create ----------
  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setError("");
    try {
      await secretsApi.create({
        title: createForm.title,
        description: createForm.description || undefined,
        rawValue: createForm.rawValue,
        category: createForm.category || undefined,
        expiresAt: toIsoOrUndefined(createForm.expiresAt),
      });
      setNotice("Entry added to the vault.");
      closePanels();
      await loadSecrets();
    } catch (err) {
      setError(extractErrorMessage(err, "Could not create the entry."));
    } finally {
      setCreating(false);
    }
  };

  // ---------- Paste bulk import ----------
  const parseBulkLine = (line: string) => {
    const parts = line.split("|").map((p) => p.trim());
    if (parts.length === 2) return { title: parts[0], category: undefined, rawValue: parts[1] };
    if (parts.length >= 3) {
      return { title: parts[0], category: parts[1] || undefined, rawValue: parts.slice(2).join("|").trim() };
    }
    return null;
  };

  const handleBulkImport = async () => {
    const lines = bulkText.split("\n").map((l) => l.trim()).filter(Boolean);
    if (lines.length === 0) return;

    setBulkSubmitting(true);
    setBulkResult(null);
    let ok = 0;
    let failed = 0;
    const errors: string[] = [];

    for (const line of lines) {
      const parsed = parseBulkLine(line);
      if (!parsed || !parsed.title || !parsed.rawValue) {
        failed++;
        errors.push(`"${line}" — expected: Title | Value  or  Title | Category | Value`);
        continue;
      }
      try {
        await secretsApi.create({
          title: parsed.title,
          rawValue: parsed.rawValue,
          category: normalizeCategory(parsed.category),
        });
        ok++;
      } catch (err) {
        failed++;
        errors.push(`"${parsed.title}" — ${extractErrorMessage(err, "failed")}`);
      }
    }

    setBulkResult({ ok, failed, errors });
    setBulkSubmitting(false);
    if (ok > 0) {
      setNotice(`${ok} ${ok === 1 ? "entry" : "entries"} imported.`);
      await loadSecrets();
    }
  };

  // ---------- CSV import ----------
  const handleCsvFile = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setCsvParseError("");
    setCsvResult(null);
    setCsvFileName(file.name);

    Papa.parse<Record<string, string>>(file, {
      header: true,
      skipEmptyLines: true,
      complete: (results) => {
        if (!results.data.length) {
          setCsvParseError("The file appears to be empty.");
          return;
        }
        const columns = results.meta.fields || [];
        setCsvColumns(columns);
        setCsvRows(results.data);

        const guess = (patterns: string[]) =>
          columns.find((c) => patterns.some((p) => c.toLowerCase().includes(p))) || "";

        setCsvMapping({
          title: guess(["title", "name", "site", "account"]),
          category: guess(["category", "type", "folder"]),
          value: guess(["password", "value", "secret", "key"]),
        });
      },
      error: (err) => {
        setCsvParseError(err.message || "Could not parse this CSV file.");
      },
    });
  };

  const handleCsvImport = async () => {
    if (!csvMapping.title || !csvMapping.value) return;

    setCsvImporting(true);
    setCsvResult(null);
    let ok = 0;
    let failed = 0;
    const errors: string[] = [];

    for (const row of csvRows) {
      const title = row[csvMapping.title]?.trim();
      const rawValue = row[csvMapping.value]?.trim();
      const categoryRaw = csvMapping.category ? row[csvMapping.category] : undefined;

      if (!title || !rawValue) {
        failed++;
        errors.push(`Row skipped — missing title or value (${JSON.stringify(row)})`);
        continue;
      }

      try {
        await secretsApi.create({
          title,
          rawValue,
          category: normalizeCategory(categoryRaw),
        });
        ok++;
      } catch (err) {
        failed++;
        errors.push(`"${title}" — ${extractErrorMessage(err, "failed")}`);
      }
    }

    setCsvResult({ ok, failed, errors });
    setCsvImporting(false);
    if (ok > 0) {
      setNotice(`${ok} ${ok === 1 ? "entry" : "entries"} imported from CSV.`);
      await loadSecrets();
    }
  };

  // ---------- Reveal / delete ----------
  const handleReveal = async (id: string) => {
    if (revealed[id]) {
      setRevealed((prev) => {
        const copy = { ...prev };
        delete copy[id];
        return copy;
      });
      return;
    }
    setRevealingId(id);
    setError("");
    try {
      const res = await secretsApi.decrypt(id);
      if (res.data.success && typeof res.data.data === "string") {
        setRevealed((prev) => ({ ...prev, [id]: res.data.data as string }));
      }
    } catch (err) {
      setError(extractErrorMessage(err, "Could not decrypt this entry."));
    } finally {
      setRevealingId(null);
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm("Permanently remove this entry from the vault registry?")) return;
    try {
      await secretsApi.remove(id);
      setSecrets((prev) => prev.filter((s) => s.id !== id));
      setRevealed((prev) => {
        const copy = { ...prev };
        delete copy[id];
        return copy;
      });
      setNotice("Entry deleted.");
    } catch (err) {
      setError(extractErrorMessage(err, "Could not delete this entry."));
    }
  };

  // ---------- Edit ----------
  const startEdit = (secret: Secret) => {
    setEditingId(secret.id);
    setEditForm({
      title: secret.title,
      category: secret.category || "",
      description: secret.description || "",
      rawValue: "",
      expiresAt: secret.expiresAt ? secret.expiresAt.slice(0, 10) : "",
    });
    setActivePanel("none");
  };

  const cancelEdit = () => {
    setEditingId(null);
    setEditForm(emptyForm);
  };

  const handleEditSubmit = async (e: FormEvent, id: string) => {
    e.preventDefault();
    setSaving(true);
    setError("");
    try {
      await secretsApi.update({
        id,
        title: editForm.title || undefined,
        category: editForm.category || undefined,
        description: editForm.description || undefined,
        newRawValue: editForm.rawValue || undefined,
        expiresAt: toIsoOrUndefined(editForm.expiresAt),
      });
      setRevealed((prev) => {
        const copy = { ...prev };
        delete copy[id];
        return copy;
      });
      setNotice("Entry updated.");
      cancelEdit();
      await loadSecrets();
    } catch (err) {
      setError(extractErrorMessage(err, "Could not update this entry."));
    } finally {
      setSaving(false);
    }
  };

  const expiringCount = secrets.filter((s) => s.hasExpiration && !s.isExpired).length;
  const categoriesUsed = new Set(secrets.map((s) => s.category).filter(Boolean)).size;

  return (
    <div className="min-h-screen">
      <header className="border-b border-line glass sticky top-0 z-10">
        <div className="max-w-4xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2.5 text-text">
            <VaultMark size={24} />
            <span className="font-medium tracking-tight text-sm">VaultGuard</span>
          </div>
          <div className="flex items-center gap-5">
            <span className="text-sm text-text-muted font-mono">{user?.username}</span>
            <Link to="/profile" className="text-sm text-text-muted hover:text-accent transition-colors">
              Profile
            </Link>
            <Link to="/audit-logs" className="text-sm text-text-muted hover:text-accent transition-colors">
              Audit log
            </Link>
            <button
              onClick={logout}
              className="inline-flex items-center gap-1.5 text-sm text-text-muted hover:text-danger transition-colors"
            >
              <LogOut size={14} />
              Sign out
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-10">
        <div className="flex flex-wrap items-end justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-medium text-text">Vault registry</h1>
            <p className="text-sm text-text-muted mt-1">
              {loading ? "Loading…" : `${secrets.length} ${secrets.length === 1 ? "secret" : "secrets"} stored`}
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Button
              variant="ghost"
              onClick={() => setActivePanel((p) => (p === "csv" ? "none" : "csv"))}
              className="gap-1.5"
            >
              <FileSpreadsheet size={15} />
              CSV import
            </Button>
            <Button
              variant="ghost"
              onClick={() => setActivePanel((p) => (p === "paste" ? "none" : "paste"))}
              className="gap-1.5"
            >
              <ClipboardList size={15} />
              Paste import
            </Button>
            <Button onClick={() => setActivePanel((p) => (p === "create" ? "none" : "create"))} className="gap-1.5">
              <Plus size={15} />
              New entry
            </Button>
          </div>
        </div>

        {!loading && secrets.length > 0 && (
          <div className="grid grid-cols-3 gap-3 mb-6">
            <div className="glass border border-line rounded-xl px-4 py-3 flex items-center gap-3">
              <ShieldCheck size={18} className="text-accent shrink-0" />
              <div>
                <p className="text-lg font-medium text-text leading-none">{secrets.length}</p>
                <p className="text-xs text-text-muted mt-1">Total secrets</p>
              </div>
            </div>
            <div className="glass border border-line rounded-xl px-4 py-3 flex items-center gap-3">
              <Layers size={18} className="text-accent-2 shrink-0" />
              <div>
                <p className="text-lg font-medium text-text leading-none">{categoriesUsed}</p>
                <p className="text-xs text-text-muted mt-1">Categories used</p>
              </div>
            </div>
            <div className="glass border border-line rounded-xl px-4 py-3 flex items-center gap-3">
              <Clock size={18} className="text-success shrink-0" />
              <div>
                <p className="text-lg font-medium text-text leading-none">{expiringCount}</p>
                <p className="text-xs text-text-muted mt-1">With expiration</p>
              </div>
            </div>
          </div>
        )}

        {notice && (
          <div className="mb-4 flex items-center gap-2 text-sm text-success bg-success/10 border border-success/25 rounded-xl px-3.5 py-2.5">
            <Check size={15} />
            {notice}
          </div>
        )}

        {error && (
          <div className="mb-6 flex items-center gap-2 text-sm text-danger bg-danger/10 border border-danger/25 rounded-xl px-3.5 py-2.5">
            <AlertTriangle size={15} />
            {error}
          </div>
        )}

        {/* Create panel */}
        {activePanel === "create" && (
          <form onSubmit={handleCreate} className="mb-8 glass border border-line rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium text-text">New entry</h2>
              <button type="button" onClick={closePanels} className="text-text-faint hover:text-text">
                <X size={16} />
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Field
                label="Title"
                required
                value={createForm.title}
                onChange={(e) => setCreateForm((p) => ({ ...p, title: e.target.value }))}
                placeholder="e.g. Gmail account"
              />
              <CategorySelect
                value={createForm.category}
                onChange={(v) => setCreateForm((p) => ({ ...p, category: v }))}
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Field
                label="Description"
                value={createForm.description}
                onChange={(e) => setCreateForm((p) => ({ ...p, description: e.target.value }))}
                placeholder="optional"
              />
              <Field
                label="Expires on"
                type="date"
                value={createForm.expiresAt}
                onChange={(e) => setCreateForm((p) => ({ ...p, expiresAt: e.target.value }))}
              />
            </div>

            <div className="space-y-1.5">
              <label className="block text-sm text-text-muted">Secret value</label>
              <textarea
                required
                rows={3}
                value={createForm.rawValue}
                onChange={(e) => setCreateForm((p) => ({ ...p, rawValue: e.target.value }))}
                placeholder="Password, API key or private note"
                className="w-full rounded-xl bg-white border border-line px-3.5 py-2.5 text-sm text-text placeholder:text-text-faint outline-none font-mono transition-all duration-200 focus:border-accent/60 focus:shadow-[0_0_0_4px_rgba(91,141,239,0.15)]"
              />
            </div>

            <Button type="submit" disabled={creating}>
              {creating ? "Saving…" : "Add to vault"}
            </Button>
          </form>
        )}

        {/* Paste import panel */}
        {activePanel === "paste" && (
          <div className="mb-8 glass border border-line rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium text-text">Paste import</h2>
              <button type="button" onClick={closePanels} className="text-text-faint hover:text-text">
                <X size={16} />
              </button>
            </div>

            <p className="text-xs text-text-muted leading-relaxed">
              One entry per line. Format: <span className="font-mono text-accent">Title | Value</span> or{" "}
              <span className="font-mono text-accent">Title | Category | Value</span>.
            </p>

            <textarea
              rows={6}
              value={bulkText}
              onChange={(e) => setBulkText(e.target.value)}
              placeholder={"Gmail account | Password | Sup3r$ecret!\nStripe key | ApiKey | sk_live_xxx..."}
              className="w-full rounded-xl bg-white border border-line px-3.5 py-2.5 text-sm text-text placeholder:text-text-faint outline-none font-mono transition-all duration-200 focus:border-accent/60 focus:shadow-[0_0_0_4px_rgba(91,141,239,0.15)]"
            />

            <Button onClick={handleBulkImport} disabled={bulkSubmitting || !bulkText.trim()} className="gap-1.5">
              <UploadCloud size={15} />
              {bulkSubmitting ? "Importing…" : "Import all lines"}
            </Button>

            {bulkResult && (
              <div className="space-y-2 pt-2 border-t border-line">
                <p className="text-sm text-text">
                  <span className="text-success">{bulkResult.ok} succeeded</span>
                  {bulkResult.failed > 0 && (
                    <>
                      {" · "}
                      <span className="text-danger">{bulkResult.failed} failed</span>
                    </>
                  )}
                </p>
                {bulkResult.errors.length > 0 && (
                  <ul className="text-xs text-text-muted space-y-1 max-h-32 overflow-y-auto">
                    {bulkResult.errors.map((e, i) => (
                      <li key={i} className="text-danger/90">
                        {e}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        )}

        {/* CSV import panel */}
        {activePanel === "csv" && (
          <div className="mb-8 glass border border-line rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium text-text">CSV import</h2>
              <button type="button" onClick={closePanels} className="text-text-faint hover:text-text">
                <X size={16} />
              </button>
            </div>

            <p className="text-xs text-text-muted leading-relaxed">
              Upload a CSV file exported from another password manager or spreadsheet. Map its columns
              below, preview the result, then import everything in one pass.
            </p>

            <label className="flex items-center justify-center gap-2 rounded-xl border border-dashed border-line bg-white px-4 py-6 text-sm text-text-muted cursor-pointer hover:border-accent/50 transition-colors">
              <UploadCloud size={16} />
              {csvFileName || "Choose a .csv file"}
              <input type="file" accept=".csv" onChange={handleCsvFile} className="hidden" />
            </label>

            {csvParseError && (
              <div className="text-sm text-danger bg-danger/10 border border-danger/25 rounded-xl px-3.5 py-2.5">
                {csvParseError}
              </div>
            )}

            {csvColumns.length > 0 && (
              <>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div className="space-y-1.5">
                    <label className="block text-sm text-text-muted">Title column</label>
                    <select
                      value={csvMapping.title}
                      onChange={(e) => setCsvMapping((p) => ({ ...p, title: e.target.value }))}
                      className="w-full rounded-xl bg-white border border-line px-3.5 py-2.5 text-sm text-text outline-none focus:border-accent/60"
                    >
                      <option value="">—</option>
                      {csvColumns.map((c) => (
                        <option key={c} value={c}>
                          {c}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="space-y-1.5">
                    <label className="block text-sm text-text-muted">Category column</label>
                    <select
                      value={csvMapping.category}
                      onChange={(e) => setCsvMapping((p) => ({ ...p, category: e.target.value }))}
                      className="w-full rounded-xl bg-white border border-line px-3.5 py-2.5 text-sm text-text outline-none focus:border-accent/60"
                    >
                      <option value="">None</option>
                      {csvColumns.map((c) => (
                        <option key={c} value={c}>
                          {c}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="space-y-1.5">
                    <label className="block text-sm text-text-muted">Value column</label>
                    <select
                      value={csvMapping.value}
                      onChange={(e) => setCsvMapping((p) => ({ ...p, value: e.target.value }))}
                      className="w-full rounded-xl bg-white border border-line px-3.5 py-2.5 text-sm text-text outline-none focus:border-accent/60"
                    >
                      <option value="">—</option>
                      {csvColumns.map((c) => (
                        <option key={c} value={c}>
                          {c}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div>
                  <p className="text-xs text-text-muted mb-2">Preview ({csvRows.length} rows detected)</p>
                  <div className="border border-line rounded-xl overflow-x-auto bg-white">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b border-line text-text-muted">
                          <th className="text-left px-3 py-2 font-medium">Title</th>
                          <th className="text-left px-3 py-2 font-medium">Category</th>
                          <th className="text-left px-3 py-2 font-medium">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {csvRows.slice(0, 5).map((row, i) => (
                          <tr key={i} className="border-b border-line last:border-0 text-text">
                            <td className="px-3 py-2">{csvMapping.title ? row[csvMapping.title] : "—"}</td>
                            <td className="px-3 py-2">
                              {csvMapping.category ? normalizeCategory(row[csvMapping.category]) : "—"}
                            </td>
                            <td className="px-3 py-2 font-mono text-text-muted">
                              {csvMapping.value ? "•".repeat(Math.min(row[csvMapping.value]?.length || 0, 14)) : "—"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <Button
                  onClick={handleCsvImport}
                  disabled={csvImporting || !csvMapping.title || !csvMapping.value}
                  className="gap-1.5"
                >
                  <UploadCloud size={15} />
                  {csvImporting ? "Importing…" : `Import ${csvRows.length} rows`}
                </Button>

                {csvResult && (
                  <div className="space-y-2 pt-2 border-t border-line">
                    <p className="text-sm text-text">
                      <span className="text-success">{csvResult.ok} succeeded</span>
                      {csvResult.failed > 0 && (
                        <>
                          {" · "}
                          <span className="text-danger">{csvResult.failed} failed</span>
                        </>
                      )}
                    </p>
                    {csvResult.errors.length > 0 && (
                      <ul className="text-xs text-text-muted space-y-1 max-h-32 overflow-y-auto">
                        {csvResult.errors.map((e, i) => (
                          <li key={i} className="text-danger/90">
                            {e}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {!loading && secrets.length === 0 && activePanel === "none" && (
          <div className="border border-dashed border-line rounded-2xl px-6 py-14 text-center">
            <p className="text-sm text-text-muted">Your vault is empty. Add your first entry to get started.</p>
          </div>
        )}

        {secrets.length > 0 && (
          <div className="space-y-3">
            {secrets.map((secret, index) => {
              const isOpen = Boolean(revealed[secret.id]);
              const isEditing = editingId === secret.id;

              if (isEditing) {
                return (
                  <form
                    key={secret.id}
                    onSubmit={(e) => handleEditSubmit(e, secret.id)}
                    className="glass border border-accent/30 rounded-2xl p-6 space-y-4"
                  >
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-medium text-accent">Editing entry</h3>
                      <button type="button" onClick={cancelEdit} className="text-text-faint hover:text-text">
                        <X size={16} />
                      </button>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <Field
                        label="Title"
                        required
                        value={editForm.title}
                        onChange={(e) => setEditForm((p) => ({ ...p, title: e.target.value }))}
                      />
                      <CategorySelect
                        value={editForm.category}
                        onChange={(v) => setEditForm((p) => ({ ...p, category: v }))}
                      />
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <Field
                        label="Description"
                        value={editForm.description}
                        onChange={(e) => setEditForm((p) => ({ ...p, description: e.target.value }))}
                      />
                      <Field
                        label="Expires on"
                        type="date"
                        value={editForm.expiresAt}
                        onChange={(e) => setEditForm((p) => ({ ...p, expiresAt: e.target.value }))}
                      />
                    </div>

                    <div className="space-y-1.5">
                      <label className="block text-sm text-text-muted">New secret value</label>
                      <textarea
                        rows={2}
                        value={editForm.rawValue}
                        onChange={(e) => setEditForm((p) => ({ ...p, rawValue: e.target.value }))}
                        placeholder="Leave blank to keep the current value"
                        className="w-full rounded-xl bg-white border border-line px-3.5 py-2.5 text-sm text-text placeholder:text-text-faint outline-none font-mono transition-all duration-200 focus:border-accent/60 focus:shadow-[0_0_0_4px_rgba(91,141,239,0.15)]"
                      />
                    </div>

                    <div className="flex items-center gap-2">
                      <Button type="submit" disabled={saving} className="gap-1.5">
                        <Check size={15} />
                        {saving ? "Saving…" : "Save changes"}
                      </Button>
                      <Button type="button" variant="ghost" onClick={cancelEdit}>
                        Cancel
                      </Button>
                    </div>
                  </form>
                );
              }

              return (
                <div
                  key={secret.id}
                  className="glass border border-line rounded-2xl px-5 py-4 flex items-center gap-4 transition-colors hover:border-accent/25"
                >
                  <span className="font-mono text-xs text-text-faint w-6 shrink-0">
                    {String(index + 1).padStart(2, "0")}
                  </span>

                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="text-sm font-medium text-text">{secret.title}</h3>
                      {secret.category && (
                        <span className="text-xs text-accent border border-accent/30 rounded-full px-2 py-0.5">
                          {secret.category}
                        </span>
                      )}
                      {secret.isExpired && (
                        <span className="text-xs text-danger border border-danger/30 rounded-full px-2 py-0.5">
                          Expired
                        </span>
                      )}
                      {!secret.isExpired && secret.hasExpiration && secret.expiresAt && (
                        <span className="text-xs text-text-faint">
                          expires {new Date(secret.expiresAt).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                    {secret.description && (
                      <p className="text-xs text-text-muted mt-0.5">{secret.description}</p>
                    )}
                    <p className="text-xs font-mono text-text-muted mt-2 break-all">
                      {isOpen ? revealed[secret.id] : "••••••••••••••••"}
                    </p>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => handleReveal(secret.id)}
                      disabled={revealingId === secret.id}
                      className="inline-flex items-center gap-1.5 text-xs text-text-muted hover:text-accent border border-line hover:border-accent/40 rounded-lg px-2.5 py-1.5 transition-colors disabled:opacity-50"
                    >
                      {isOpen ? <LockOpen size={13} /> : <Lock size={13} />}
                      {revealingId === secret.id ? "…" : isOpen ? "Hide" : "Reveal"}
                    </button>
                    <button
                      onClick={() => startEdit(secret)}
                      className="inline-flex items-center gap-1.5 text-xs text-text-muted hover:text-accent-2 border border-line hover:border-accent-2/40 rounded-lg px-2.5 py-1.5 transition-colors"
                    >
                      <Pencil size={13} />
                      Edit
                    </button>
                    <button
                      onClick={() => handleDelete(secret.id)}
                      className="inline-flex items-center gap-1.5 text-xs text-text-muted hover:text-danger border border-line hover:border-danger/40 rounded-lg px-2.5 py-1.5 transition-colors"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </main>
    </div>
  );
}