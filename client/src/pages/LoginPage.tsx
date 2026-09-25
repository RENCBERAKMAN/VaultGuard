import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { VaultMark } from "../components/VaultMark";
import { Field } from "../components/ui/Field";
import { Button } from "../components/ui/Button";

export default function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    const result = await login({ email, password, rememberMe });
    setSubmitting(false);
    if (result.success) {
      navigate("/dashboard");
    } else {
      setError(result.message);
    }
  };

  return (
    <div className="min-h-screen flex flex-col md:flex-row">
      <div className="relative md:w-[42%] flex flex-col justify-between overflow-hidden border-b md:border-b-0 md:border-r border-line px-8 py-10 md:py-14">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -right-32 -top-32 h-96 w-96 rounded-full opacity-40"
          style={{ background: "radial-gradient(circle, rgba(111,227,255,0.25), transparent 70%)" }}
        />
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -left-20 bottom-0 h-72 w-72 rounded-full opacity-30"
          style={{ background: "radial-gradient(circle, rgba(155,140,255,0.25), transparent 70%)" }}
        />

        <div className="relative flex items-center gap-3 text-text">
          <VaultMark size={32} />
          <span className="font-medium tracking-tight">VaultGuard</span>
        </div>

        <div className="relative mt-10 md:mt-0 max-w-sm">
          <h1 className="text-2xl md:text-3xl font-medium text-text leading-snug">
            Every secret, one orbit, fully secured.
          </h1>
          <p className="mt-3 text-sm text-text-muted leading-relaxed">
            Passwords, API keys and private notes are encrypted with AES-256-GCM. Every access is recorded.
          </p>

          <dl className="mt-8 space-y-4 border-t border-line pt-6">
            <div className="flex items-start justify-between gap-4">
              <dt className="text-sm text-text-muted">Encryption</dt>
              <dd className="text-sm text-accent font-mono">AES-256-GCM</dd>
            </div>
            <div className="flex items-start justify-between gap-4">
              <dt className="text-sm text-text-muted">Session</dt>
              <dd className="text-sm text-accent font-mono">JWT + refresh</dd>
            </div>
            <div className="flex items-start justify-between gap-4">
              <dt className="text-sm text-text-muted">Access log</dt>
              <dd className="text-sm text-accent font-mono">Every read is logged</dd>
            </div>
          </dl>
        </div>

        <p className="relative text-xs text-text-faint">© {new Date().getFullYear()} VaultGuard</p>
      </div>

      <div className="flex-1 flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm glass border border-line rounded-2xl p-8">
          <h2 className="text-lg font-medium text-text mb-1">Sign in to your vault</h2>
          <p className="text-sm text-text-muted mb-8">Enter your email and password to continue.</p>

          <form onSubmit={handleSubmit} className="space-y-5">
            {error && (
              <div className="text-sm text-danger bg-danger/10 border border-danger/25 rounded-xl px-3.5 py-2.5">
                {error}
              </div>
            )}

            <Field
              label="Email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@vaultguard.com"
              autoComplete="username"
            />

            <Field
              label="Password"
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              autoComplete="current-password"
            />

            <label className="flex items-center gap-2.5 text-sm text-text-muted select-none">
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className="h-4 w-4 rounded-sm border-line bg-panel accent-accent"
              />
              Remember me
            </label>

            <Button type="submit" disabled={submitting} className="w-full">
              {submitting ? "Verifying…" : "Sign in"}
            </Button>

            <p className="text-sm text-text-muted pt-2">
              Don&apos;t have an account?{" "}
              <Link to="/register" className="text-accent hover:text-accent-2">
                Create a vault
              </Link>
            </p>
          </form>
        </div>
      </div>
    </div>
  );
}