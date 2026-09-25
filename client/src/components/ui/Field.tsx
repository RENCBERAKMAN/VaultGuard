import type { InputHTMLAttributes } from "react";

interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  hint?: string;
}

export function Field({ label, hint, id, className = "", ...props }: FieldProps) {
  const inputId = id || label.toLowerCase().replace(/\s+/g, "-");
  return (
    <div className="space-y-1.5">
      <label htmlFor={inputId} className="block text-sm text-text-muted">
        {label}
      </label>
      <input
        id={inputId}
        {...props}
        className={`w-full rounded-xl bg-white border border-line px-3.5 py-2.5 text-sm text-text placeholder:text-text-faint outline-none transition-all duration-200 focus:border-accent/60 focus:shadow-[0_0_0_4px_rgba(91,141,239,0.15)] disabled:opacity-50 disabled:cursor-not-allowed disabled:bg-void ${className}`}
      />
      {hint && <p className="text-xs text-text-faint">{hint}</p>}
    </div>
  );
}