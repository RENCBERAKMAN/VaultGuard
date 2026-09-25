import { useState, type FormEvent, type ChangeEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { VaultMark } from "../components/VaultMark";
import { Field } from "../components/ui/Field";
import { Button } from "../components/ui/Button";

interface FormState {
  email: string;
  username: string;
  password: string;
  confirmPassword: string;
}

export default function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState<FormState>({
    email: "",
    username: "",
    password: "",
    confirmPassword: "",
  });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const update = (key: keyof FormState) => (e: ChangeEvent<HTMLInputElement>) => {
    setForm((prev) => ({ ...prev, [key]: e.target.value }));
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (form.password !== form.confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setSubmitting(true);
    const result = await register(form);
    setSubmitting(false);

    if (result.success) {
      setSuccess(result.message || "Vault created. You can now sign in.");
      setTimeout(() => navigate("/login"), 1400);
    } else {
      setError(result.message);
    }
  };

  return (
    <div className="min-h-screen flex flex-col md:flex-row">
      <div className="relative md:w-[42%] flex flex-col justify-between overflow-hidden border-b md:border-b-0 md:border-r border-line px-8 py-10 md:py-14">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -left-32 -bottom-32 h-96 w-96 rounded-full opacity-40"
          style={{ background: "radial-gradient(circle, rgba(155,140,255,0.25), transparent 70%)" }}
        />
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -right-20 top-0 h-72 w-72 rounded-full opacity-30"
          style={{ background: "radial-gradient(circle, rgba(111,227,255,0.25), transparent 70%)" }}
        />

        <div className="relative flex items-center gap-3 text-text">
          <VaultMark size={32} />
          <span className="font-medium tracking-tight">VaultGuard</span>
        </div>

        <div className="relative mt-10 md:mt-0 max-w-sm">
          <h1 className="text-2xl md:text-3xl font-medium text-text leading-snug">
            Open a new vault.
          </h1>
          <p className="mt-3 text-sm text-text-muted leading-relaxed">
            Once registered, you can securely store passwords, API keys and
            private notes in your vault.
          </p>

          <ol className="mt-8 space-y-4 border-t border-line pt-6">
            <li className="flex items-start gap-3 text-sm">
              <span className="font-mono text-accent">01</span>
              <span className="text-text-muted">Create your account</span>
            </li>
            <li className="flex items-start gap-3 text-sm">
              <span className="font-mono text-accent">02</span>
              <span className="text-text-muted">Sign in</span>
            </li>
            <li className="flex items-start gap-3 text-sm">
              <span className="font-mono text-accent">03</span>
              <span className="text-text-muted">Add your first secret to the vault</span>
            </li>
          </ol>
        </div>

        <p className="relative text-xs text-text-faint">© {new Date().getFullYear()} VaultGuard</p>
      </div>

      <div className="flex-1 flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm glass border border-line rounded-2xl p-8">
          <h2 className="text-lg font-medium text-text mb-1">Create your vault</h2>
          <p className="text-sm text-text-muted mb-8">Set up your account with a few details.</p>

          <form onSubmit={handleSubmit} className="space-y-5">
            {error && (
              <div className="text-sm text-danger bg-danger/10 border border-danger/25 rounded-xl px-3.5 py-2.5">
                {error}
              </div>
            )}
            {success && (
              <div className="text-sm text-success bg-success/10 border border-success/25 rounded-xl px-3.5 py-2.5">
                {success}
              </div>
            )}

            <Field
              label="Email"
              type="email"
              required
              value={form.email}
              onChange={update("email")}
              placeholder="you@vaultguard.com"
              autoComplete="email"
            />

            <Field
              label="Username"
              type="text"
              required
              minLength={3}
              value={form.username}
              onChange={update("username")}
              placeholder="letters, numbers, . _ -"
              autoComplete="username"
            />

            <Field
              label="Password"
              type="password"
              required
              minLength={8}
              value={form.password}
              onChange={update("password")}
              placeholder="Upper+lowercase, digit, special character"
              autoComplete="new-password"
            />

            <Field
              label="Confirm password"
              type="password"
              required
              value={form.confirmPassword}
              onChange={update("confirmPassword")}
              placeholder="••••••••"
              autoComplete="new-password"
            />

            <Button type="submit" disabled={submitting} className="w-full">
              {submitting ? "Creating…" : "Create vault"}
            </Button>

            <p className="text-sm text-text-muted pt-2">
              Already have an account?{" "}
              <Link to="/login" className="text-accent hover:text-accent-2">
                Sign in
              </Link>
            </p>
          </form>
        </div>
      </div>
    </div>
  );
}