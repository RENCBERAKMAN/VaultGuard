import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, ShieldAlert, Check } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { usersApi } from "../api/users";
import { extractErrorMessage } from "../lib/errors";
import { VaultMark } from "../components/VaultMark";
import { Field } from "../components/ui/Field";
import { Button } from "../components/ui/Button";

export default function ProfilePage() {
  const { user, refreshUser, logout } = useAuth();

  const [profileForm, setProfileForm] = useState({
    firstName: user?.firstName || "",
    lastName: user?.lastName || "",
    phoneNumber: user?.phoneNumber || "",
  });
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileNotice, setProfileNotice] = useState("");
  const [profileError, setProfileError] = useState("");

  const [pwForm, setPwForm] = useState({ oldPassword: "", newPassword: "", confirmPassword: "" });
  const [pwSaving, setPwSaving] = useState(false);
  const [pwNotice, setPwNotice] = useState("");
  const [pwError, setPwError] = useState("");

  const [loggingOutAll, setLoggingOutAll] = useState(false);

  const handleProfileSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setProfileSaving(true);
    setProfileError("");
    setProfileNotice("");
    try {
      await usersApi.updateProfile(profileForm);
      await refreshUser();
      setProfileNotice("Profile updated.");
    } catch (err) {
      setProfileError(extractErrorMessage(err, "Could not update your profile."));
    } finally {
      setProfileSaving(false);
    }
  };

  const handlePasswordSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setPwError("");
    setPwNotice("");

    if (pwForm.newPassword !== pwForm.confirmPassword) {
      setPwError("New passwords do not match.");
      return;
    }

    setPwSaving(true);
    try {
      await usersApi.changePassword({
        oldPassword: pwForm.oldPassword,
        newPassword: pwForm.newPassword,
      });
      setPwNotice("Password changed successfully.");
      setPwForm({ oldPassword: "", newPassword: "", confirmPassword: "" });
    } catch (err) {
      setPwError(extractErrorMessage(err, "Could not change your password."));
    } finally {
      setPwSaving(false);
    }
  };

  const handleLogoutAll = async () => {
    if (!window.confirm("This will sign you out on every device, including this one. Continue?")) return;
    setLoggingOutAll(true);
    try {
      await usersApi.logoutAllDevices();
    } catch {
      // proceed to local logout regardless
    } finally {
      await logout();
    }
  };

  return (
    <div className="min-h-screen">
      <header className="border-b border-line glass sticky top-0 z-10">
        <div className="max-w-3xl mx-auto px-6 py-4 flex items-center justify-between">
          <Link to="/dashboard" className="flex items-center gap-2.5 text-text hover:text-accent transition-colors">
            <ArrowLeft size={16} />
            <VaultMark size={22} />
            <span className="font-medium tracking-tight text-sm">VaultGuard</span>
          </Link>
          <span className="text-sm text-text-muted font-mono">{user?.username}</span>
        </div>
      </header>

      <main className="max-w-3xl mx-auto px-6 py-10 space-y-8">
        <div>
          <h1 className="text-xl font-medium text-text">Account settings</h1>
          <p className="text-sm text-text-muted mt-1">Manage your profile, password and active sessions.</p>
        </div>

        <form onSubmit={handleProfileSubmit} className="glass border border-line rounded-2xl p-6 space-y-4">
          <h2 className="text-sm font-medium text-text">Profile</h2>

          {profileNotice && (
            <div className="flex items-center gap-2 text-sm text-success bg-success/10 border border-success/25 rounded-xl px-3.5 py-2.5">
              <Check size={15} />
              {profileNotice}
            </div>
          )}
          {profileError && (
            <div className="text-sm text-danger bg-danger/10 border border-danger/25 rounded-xl px-3.5 py-2.5">
              {profileError}
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Field label="Email" value={user?.email || ""} disabled hint="Email cannot be changed here." />
            <Field label="Username" value={user?.username || ""} disabled hint="Username is fixed." />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Field
              label="First name"
              value={profileForm.firstName}
              onChange={(e) => setProfileForm((p) => ({ ...p, firstName: e.target.value }))}
            />
            <Field
              label="Last name"
              value={profileForm.lastName}
              onChange={(e) => setProfileForm((p) => ({ ...p, lastName: e.target.value }))}
            />
          </div>

          <Field
            label="Phone number"
            value={profileForm.phoneNumber}
            onChange={(e) => setProfileForm((p) => ({ ...p, phoneNumber: e.target.value }))}
            placeholder="optional"
          />

          <Button type="submit" disabled={profileSaving}>
            {profileSaving ? "Saving…" : "Save profile"}
          </Button>
        </form>

        <form onSubmit={handlePasswordSubmit} className="glass border border-line rounded-2xl p-6 space-y-4">
          <h2 className="text-sm font-medium text-text">Change password</h2>

          {pwNotice && (
            <div className="flex items-center gap-2 text-sm text-success bg-success/10 border border-success/25 rounded-xl px-3.5 py-2.5">
              <Check size={15} />
              {pwNotice}
            </div>
          )}
          {pwError && (
            <div className="text-sm text-danger bg-danger/10 border border-danger/25 rounded-xl px-3.5 py-2.5">
              {pwError}
            </div>
          )}

          <Field
            label="Current password"
            type="password"
            required
            value={pwForm.oldPassword}
            onChange={(e) => setPwForm((p) => ({ ...p, oldPassword: e.target.value }))}
            autoComplete="current-password"
          />
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Field
              label="New password"
              type="password"
              required
              minLength={8}
              value={pwForm.newPassword}
              onChange={(e) => setPwForm((p) => ({ ...p, newPassword: e.target.value }))}
              autoComplete="new-password"
            />
            <Field
              label="Confirm new password"
              type="password"
              required
              value={pwForm.confirmPassword}
              onChange={(e) => setPwForm((p) => ({ ...p, confirmPassword: e.target.value }))}
              autoComplete="new-password"
            />
          </div>

          <Button type="submit" disabled={pwSaving}>
            {pwSaving ? "Updating…" : "Change password"}
          </Button>
        </form>

        <div className="glass border border-danger/25 rounded-2xl p-6 space-y-3">
          <h2 className="text-sm font-medium text-danger flex items-center gap-2">
            <ShieldAlert size={16} />
            Danger zone
          </h2>
          <p className="text-sm text-text-muted">
            Sign out of every active session across all devices. You will need to sign in again here too.
          </p>
          <Button variant="danger" onClick={handleLogoutAll} disabled={loggingOutAll}>
            {loggingOutAll ? "Signing out everywhere…" : "Sign out of all devices"}
          </Button>
        </div>
      </main>
    </div>
  );
}